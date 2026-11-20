package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
// and to the SHA-256 of the agent file that registration was about to
// create. An artifact under the name is that registration's exactly when it
// matches its commitment. Three outcomes:
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

// leftover is what exists under a name and whether an intent owns it.
type leftover struct {
	keyExists, keyOwned   bool
	fileExists, fileOwned bool
	own                   secrets.Ownership
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
	raw, err := os.ReadFile(r.plan.Path)
	switch {
	case err == nil:
		l.fileExists = true
		sum := sha256.Sum256(raw)
		l.fileOwned = c.FileSHA256 != "" && hex.EncodeToString(sum[:]) == c.FileSHA256 && samePath(c.AgentFile, r.plan.AbsPath)
	case !errors.Is(err, os.ErrNotExist):
		return l, fmt.Errorf("reading %s: %w", r.plan.Path, err)
	}
	return l, nil
}

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

func (r *registrationRun) resolveOne(in *registration.Unresolved) (string, error) {
	head := fmt.Sprintf("an earlier registration of %q (tenant %s, signed intent %s of %s) has no completion or rollback record", in.Name, in.Tenant, in.IntentID, in.At.UTC().Format(time.RFC3339))
	if !registration.LockSupported {
		return "", fmt.Errorf("%s. On this platform it cannot be established that it is not still running, so nothing was changed", head)
	}
	if !in.Verified {
		return "", fmt.Errorf("%s, and that intent record does not verify (it was changed after signing): it proves nothing and justifies no recovery. Nothing was changed. Verify the evidence store first: talon audit verify %s", head, in.IntentID)
	}
	l, err := r.inspect(in)
	if err != nil {
		return "", fmt.Errorf("%s; inspecting what exists under the name failed (nothing was changed): %w", head, err)
	}
	legacy := in.Commitments.KeyOwnershipToken == "" && in.Commitments.FileSHA256 == ""
	switch {
	case l.owned() && !l.foreign():
		return r.recoverOwned(in, l)
	case !l.owned() && (l.none() || !legacy):
		// It left nothing: none of the artifacts its intent committed to
		// exists. Whatever is under the name is not its own.
		note := "observed now: neither the key version nor the agent file its signed intent committed to exists"
		if !l.none() {
			note += " (what is under the name now was created by something else and was not touched)"
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
		if err := os.Remove(r.plan.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			left = append(left, fmt.Sprintf("the agent file %s could not be removed (%v)", r.plan.Path, err))
		} else {
			_ = os.Remove(r.plan.Dir) // only when empty: nothing else in it is touched
			did = append(did, "removed the agent file (its SHA-256 equals the one in the signed intent)")
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
	describe := func(exists, owned bool, what, proof string) {
		switch {
		case exists && owned:
			facts = append(facts, what+": is the one that registration created ("+proof+")")
		case exists && legacy:
			facts = append(facts, what+": exists; that intent records nothing to compare it with, so who created it is not established")
		case exists:
			facts = append(facts, what+": exists and is NOT the one that registration committed to ("+proof+" differs); something else created it")
		}
	}
	describe(l.keyExists, l.keyOwned, fmt.Sprintf("vault secret %q", plan.SecretName), "the vault ownership token in the signed intent")
	describe(l.fileExists, l.fileOwned, "agent file "+plan.Path, "the SHA-256 in the signed intent")
	return fmt.Errorf("%s. Under the name now: %s. Because not everything under the name is proven to be that registration's, NOTHING was changed and nothing was written: 'talon agents add' removes only what a signed intent proves a registration created. Establish who uses these (talon agents show %s; talon secrets list) before changing them, or register under another name", head, strings.Join(facts, "; "), plan.Name)
}
