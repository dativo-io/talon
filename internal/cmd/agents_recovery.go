package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/registration"
	"github.com/dativo-io/talon/internal/secrets"
)

// Resolution of earlier registrations of a name that never reached a
// terminal record (#567 review). It runs under the registration lock, which
// is what makes its first statement true: no registration is running, so an
// intent without a terminal record belongs to a process that died (or that
// could not write its terminal record), never to one that is still working.
//
// What it removes is decided by PROOF, never by the existence of the intent:
// the signed intent commits to the vault ownership token of the key version
// and, for the agent file, to its path, its SHA-256 and the random
// registration marker written into it. The marker matters: without it the
// generated file is the same for every registration of the same name, owner
// and tenant, so a digest alone would also match a file an operator created
// by hand. An artifact under the name is that registration's exactly when
// it matches its commitment. Three outcomes:
//
//   - every artifact under the name is proven to be that registration's:
//     exactly those are removed and it is recorded as rolled back;
//   - none of its committed artifacts exists: it left nothing, and is
//     recorded as rolled back without touching anything (what IS under the
//     name belongs to someone else and is judged like any occupied name);
//   - some artifact is its own and another is not, or the intent proves
//     nothing (it does not verify, or carries no commitments): nothing is
//     changed, and the error says what exists and what was compared. It
//     never tells the operator to delete something.
//
// What this proof is, and is not: the bytes at the committed path equal the
// bytes this registration generated, marker included, in a regular file
// that is not reached through a symbolic link. A copy of the file made
// byte for byte, marker included, cannot be told from the original by its
// content; nothing here claims otherwise.

// leftover is what exists under a name and whether an intent owns it.
type leftover struct {
	keyExists, keyOwned   bool
	fileExists, fileOwned bool
	own                   secrets.Ownership
	// fileInfo identifies the file that was inspected (set when fileOwned),
	// so that a removal removes that very file and nothing put in its place.
	fileInfo os.FileInfo
	// fileWhy says why a file that exists is not attributed to the intent.
	fileWhy string
}

func (l leftover) owned() bool { return l.keyOwned || l.fileOwned }
func (l leftover) foreign() bool {
	return (l.keyExists && !l.keyOwned) || (l.fileExists && !l.fileOwned)
}
func (l leftover) none() bool { return !l.keyExists && !l.fileExists }

// inspect reads what exists under the plan's name and compares it with the
// intent's commitments. It changes nothing.
func (r *registrationRun) inspect(in *registration.Unresolved) (leftover, error) {
	var l leftover
	c := in.Commitments
	if _, err := r.vault.Metadata(r.ctx, r.plan.SecretName); err == nil {
		l.keyExists = true
	} else if !errors.Is(err, secrets.ErrSecretNotFound) {
		return l, fmt.Errorf("reading the secrets vault: %w", err)
	}
	if l.keyExists && c.SecretName == r.plan.SecretName && c.KeyOwnershipToken != "" {
		if own, err := r.vault.OwnershipFromToken(r.plan.SecretName, c.KeyOwnershipToken); err == nil {
			owned, err := r.vault.Owns(r.ctx, own)
			if err != nil {
				return l, err
			}
			l.keyOwned, l.own = owned, own
		}
	}
	var err error
	l.fileExists, l.fileOwned, l.fileInfo, l.fileWhy, err = fileOwnedBy(r.plan, c)
	return l, err
}

// fileOwnedBy reports whether something exists at the plan's agent file path
// and whether it is the file the intent committed to. Every part of the
// commitment must hold: the path, the registration marker in the file, the
// digest of the whole file, and the artifact must be a regular file in a
// real directory (a symbolic link at the file or at the use case's
// directory is never followed for a deletion). why explains a "no".
func fileOwnedBy(plan *agentsAddPlan, c registration.Commitments) (exists, owned bool, info os.FileInfo, why string, err error) {
	info, err = os.Lstat(plan.Path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return false, false, nil, "", nil
	case err != nil:
		return false, false, nil, "", fmt.Errorf("reading %s: %w", plan.Path, err)
	}
	if why := notARegularFileInARealDir(plan, info); why != "" {
		return true, false, nil, why, nil
	}
	if c.Marker == "" {
		return true, false, nil, "that intent records no registration marker (it was written by an earlier version), so nothing ties a file to it", nil
	}
	if !samePath(c.AgentFile, plan.AbsPath) {
		return true, false, nil, "that intent committed to another path (" + c.AgentFile + ")", nil
	}
	f, err := os.Open(plan.Path)
	if err != nil {
		return true, false, nil, "", fmt.Errorf("reading %s: %w", plan.Path, err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return true, false, nil, "", fmt.Errorf("reading %s: %w", plan.Path, err)
	}
	if !os.SameFile(info, opened) {
		return true, false, nil, "it was replaced while it was being inspected", nil
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxAgentFileBytes+1))
	if err != nil {
		return true, false, nil, "", fmt.Errorf("reading %s: %w", plan.Path, err)
	}
	if !bytes.Contains(raw, []byte(registrationMarkerPrefix+c.Marker+"\n")) {
		return true, false, nil, "it does not carry that registration's marker: something else created it", nil
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != c.FileSHA256 {
		return true, false, nil, "it carries that registration's marker but its content differs from what the signed intent committed to: it was changed since", nil
	}
	return true, true, info, "", nil
}

// notARegularFileInARealDir says why the artifact at the plan's path is not
// something a deletion may act on ("" when it is a regular file in a real
// directory).
func notARegularFileInARealDir(plan *agentsAddPlan, info os.FileInfo) string {
	if info.Mode()&os.ModeSymlink != 0 {
		return "it is a symbolic link, which is never followed or removed"
	}
	if !info.Mode().IsRegular() {
		return "it is not a regular file"
	}
	if dir, err := os.Lstat(plan.Dir); err != nil || dir.Mode()&os.ModeSymlink != 0 || !dir.IsDir() {
		return "its directory " + plan.Dir + " is a symbolic link or not a directory, so the path may lead somewhere else"
	}
	return ""
}

// maxAgentFileBytes bounds how much of a file recovery reads to compare it
// with a commitment. A generated agent file is a few hundred bytes.
const maxAgentFileBytes = 1 << 20

func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// resolveUnresolved resolves every earlier unresolved registration of the
// plan's name and returns what was done, one line each. An error means that
// one of them could not be resolved safely; nothing of it was changed.
func (r *registrationRun) resolveUnresolved() ([]string, error) {
	var done []string
	if r.plan.UnresolvedIncomplete {
		return nil, fmt.Errorf("the evidence store holds more unresolved registrations than one lookup reads, so the registrations of %q cannot be listed completely; nothing was written. Run 'talon doctor' for the list", r.plan.Name)
	}
	for i := range r.plan.Unresolved {
		msg, err := r.resolveOne(&r.plan.Unresolved[i])
		if err != nil {
			return nil, err
		}
		done = append(done, msg)
	}
	return done, nil
}

// judgeable reports why an unresolved registration cannot be judged from
// this run at all (nil when it can). Nothing is inspected or changed.
func (r *registrationRun) judgeable(in *registration.Unresolved, head string) error {
	if !registration.LockSupported {
		return fmt.Errorf("%s. On this platform it cannot be established that it is not still running, so nothing was changed", head)
	}
	if !in.Verified {
		return fmt.Errorf("%s, and that intent record does not verify (it was changed after signing): it proves nothing and justifies no recovery. Nothing was changed. Verify the evidence store first: talon audit verify %s", head, in.IntentID)
	}
	// The intent committed to an agent file at another path than this run
	// uses (the same data directory with another agents_dir). What is at
	// THAT path is not inspected here, so nothing may be stated or recorded
	// about it, and its key is not removed while its file may be in use.
	if c := in.Commitments; c.AgentFile != "" && !samePath(c.AgentFile, r.plan.AbsPath) {
		return fmt.Errorf("%s, and its signed intent committed to another agent file (%s) than this run would write (%s): it was started with another agents_dir. What is at that path was not inspected, so nothing was changed and nothing was recorded. Run the registration with the agents_dir that one used: it is resolved there", head, c.AgentFile, r.plan.AbsPath)
	}
	return nil
}

func (r *registrationRun) resolveOne(in *registration.Unresolved) (string, error) {
	head := fmt.Sprintf("an earlier registration of %q (tenant %s, signed intent %s of %s) has no completion or rollback record", in.Name, in.Tenant, in.IntentID, in.At.UTC().Format(time.RFC3339))
	if err := r.judgeable(in, head); err != nil {
		return "", err
	}
	l, err := r.inspect(in)
	if err != nil {
		return "", fmt.Errorf("%s; inspecting what exists under the name failed (nothing was changed): %w", head, err)
	}
	// Something exists that the intent says nothing comparable about (an
	// intent of an earlier version: no ownership token, or no registration
	// marker). Whose it is cannot be established.
	unknown := (l.keyExists && in.Commitments.KeyOwnershipToken == "") || (l.fileExists && in.Commitments.Marker == "")
	legacy := in.Commitments.KeyOwnershipToken == "" && in.Commitments.Marker == ""
	switch {
	case l.owned() && !l.foreign():
		return r.recoverOwned(in, l)
	case !l.owned() && !unknown:
		// It left nothing: none of the artifacts its intent committed to
		// exists. Whatever is under the name is not what it committed to.
		note := "observed now: neither the key version nor the agent file its signed intent committed to exists"
		if !l.none() {
			note += " (what is under the name now is not what that intent committed to and was not touched)"
		}
		if _, err := r.recordFor(in.Correlation, in.Tenant, registration.TypeRolledBack, "cause: the registration did not finish (its process is not running: the registration lock was free)", note, "recorded by the next registration of this name"); err != nil {
			return "", fmt.Errorf("%s; recording it as rolled back failed (nothing else was written): %w", head, err)
		}
		return fmt.Sprintf("the unfinished registration of %s (intent %s) left nothing of its own and is now recorded as rolled back", in.At.UTC().Format(time.RFC3339), in.IntentID), nil
	}
	return "", notOwnedError(r.plan, head, l, legacy)
}

// recoverOwned removes exactly the artifacts the intent is proven to have
// created and records the registration as rolled back.
func (r *registrationRun) recoverOwned(in *registration.Unresolved, l leftover) (string, error) {
	var did, left []string
	if l.fileOwned {
		// Remove the very file that was inspected, not whatever is at the
		// path by now.
		now, err := os.Lstat(r.plan.Path)
		switch {
		case err != nil || !os.SameFile(l.fileInfo, now) || !now.ModTime().Equal(l.fileInfo.ModTime()) || now.Size() != l.fileInfo.Size():
			left = append(left, fmt.Sprintf("the agent file %s changed after it was inspected and was not removed", r.plan.Path))
		default:
			if err := os.Remove(r.plan.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				left = append(left, fmt.Sprintf("the agent file %s could not be removed (%v)", r.plan.Path, err))
			} else {
				_ = os.Remove(r.plan.Dir) // only when empty: nothing else in it is touched
				did = append(did, "removed the agent file (it carries the registration marker and has the SHA-256 the signed intent committed to)")
			}
		}
	}
	if l.keyOwned {
		removed, err := r.vault.DeleteOwned(r.ctx, l.own)
		switch {
		case err != nil:
			left = append(left, fmt.Sprintf("the key version stored as vault secret %q could not be removed (%v)", r.plan.SecretName, err))
		case removed:
			did = append(did, "removed the key version (its vault ownership token equals the one in the signed intent; the key was never shown)")
		default:
			did = append(did, "the key version was already gone")
		}
	}
	notes := []string{"cause: the registration did not finish (its process is not running: the registration lock was free)", "recovery: " + strings.Join(did, "; ")}
	if len(left) > 0 {
		notes = append(notes, "NOT removed: "+strings.Join(left, "; "))
	}
	notes = append(notes, "recorded by the next registration of this name")
	if _, err := r.recordFor(in.Correlation, in.Tenant, registration.TypeRolledBack, notes...); err != nil {
		return "", fmt.Errorf("the unfinished registration (intent %s) was cleaned up (%s) but could not be recorded as rolled back (nothing else was written): %w", in.IntentID, strings.Join(did, "; "), err)
	}
	if len(left) > 0 {
		return "", fmt.Errorf("the unfinished registration (intent %s) could not be cleaned up completely: %s. It is recorded as rolled back with that note; nothing else was written", in.IntentID, strings.Join(left, "; "))
	}
	return fmt.Sprintf("the interrupted registration of %s (intent %s) is now recorded as rolled back: %s", in.At.UTC().Format(time.RFC3339), in.IntentID, strings.Join(did, "; ")), nil
}

// notOwnedError explains why nothing was changed: something exists under
// the name that the unfinished registration is not proven to have created.
// It states facts and never recommends a deletion: an unfinished intent is
// not a reason to delete an artifact.
func notOwnedError(plan *agentsAddPlan, head string, l leftover, legacy bool) error {
	var facts []string
	describe := func(exists, owned bool, what, proof, why string) {
		switch {
		case exists && owned:
			facts = append(facts, what+": is the one that registration created ("+proof+")")
		case exists && why != "":
			facts = append(facts, what+": exists and is NOT attributed to that registration: "+why)
		case exists && legacy:
			facts = append(facts, what+": exists; that intent records nothing to compare it with, so who created it is not established")
		case exists:
			facts = append(facts, what+": exists and is NOT the one that registration committed to ("+proof+" differs); something else created it")
		}
	}
	describe(l.keyExists, l.keyOwned, fmt.Sprintf("vault secret %q", plan.SecretName), "the vault ownership token in the signed intent", "")
	describe(l.fileExists, l.fileOwned, "agent file "+plan.Path, "the registration marker, the path and the SHA-256 in the signed intent", l.fileWhy)
	return fmt.Errorf("%s. Under the name now: %s. Because not everything under the name is proven to be that registration's, NOTHING was changed and nothing was written: 'talon agents add' removes only what a signed intent proves a registration created. Establish who uses these (talon agents show %s; talon secrets list) before changing them, or register under another name", head, strings.Join(facts, "; "), plan.Name)
}
