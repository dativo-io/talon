package runtimestatus

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultInterval is the heartbeat period.
const DefaultInterval = 5 * time.Second

// pruneAge removes this installation's records of processes that stopped or
// went silent long ago, so the directory stays bounded across restarts.
const pruneAge = 7 * 24 * time.Hour

// Publisher writes one process instance's record.
type Publisher struct {
	dir      string
	interval time.Duration
	base     Record
	snapshot func(*Record)
	now      func() time.Time
	seq      uint64
}

// NewPublisher prepares a publisher for dataDir. base carries the static
// fields (installation, roles, version, configs); snapshot, when non-nil,
// fills the live fields (catalog generation and reload state) before every
// write.
func NewPublisher(dataDir string, interval time.Duration, base Record, snapshot func(*Record)) (*Publisher, error) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	base.Schema = SchemaVersion
	base.InstanceID = hex.EncodeToString(id)
	base.PID = os.Getpid()
	if h, err := os.Hostname(); err == nil {
		base.Host = h
	}
	base.IntervalSeconds = int(interval / time.Second)
	if base.IntervalSeconds < 1 {
		base.IntervalSeconds = 1
	}
	if base.StartedAt.IsZero() {
		base.StartedAt = time.Now().UTC()
	}
	dir := filepath.Join(dataDir, DirName)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("runtime status: %w", err)
	}
	return &Publisher{dir: dir, interval: interval, base: base, snapshot: snapshot, now: func() time.Time { return time.Now().UTC() }}, nil
}

// InstanceID identifies this process instance.
func (p *Publisher) InstanceID() string { return p.base.InstanceID }

// Run writes the record immediately, then every interval, until ctx is done;
// then it writes a final record with state "stopped". Write errors are
// returned by the first write only (the caller logs them); later failures
// keep retrying on the next tick, because a missed heartbeat is reported by
// the reader as staleness, which is the truth.
func (p *Publisher) Run(ctx context.Context) error {
	p.prune()
	if err := p.write(StateRunning); err != nil {
		return err
	}
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = p.write(StateStopped)
			return nil
		case <-t.C:
			_ = p.write(StateRunning)
		}
	}
}

func (p *Publisher) write(state string) error {
	rec := p.base
	if p.snapshot != nil {
		p.snapshot(&rec)
	}
	p.seq++
	rec.Sequence = p.seq
	rec.State = state
	rec.WrittenAt = p.now()
	if state == StateStopped {
		t := rec.WrittenAt
		rec.StoppedAt = &t
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	final := filepath.Join(p.dir, rec.InstanceID+".json")
	tmp, err := os.CreateTemp(p.dir, "."+rec.InstanceID+"-*.tmp")
	if err != nil {
		return fmt.Errorf("runtime status: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("runtime status: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("runtime status: %w", err)
	}
	// rename is atomic within the directory: a reader sees the old or the
	// new record, never a partial one.
	if err := os.Rename(tmp.Name(), final); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("runtime status: %w", err)
	}
	return nil
}

// prune removes this installation's records last written more than pruneAge
// ago, and leftover temp files. Other installations' records are left alone.
func (p *Publisher) prune() {
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		return
	}
	cutoff := p.now().Add(-pruneAge)
	for _, e := range entries {
		name := e.Name()
		path := filepath.Join(p.dir, name)
		if strings.HasSuffix(name, ".tmp") {
			if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
				_ = os.Remove(path)
			}
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		rec, err := readRecord(path)
		if err != nil || rec.Installation.KeyFingerprint != p.base.Installation.KeyFingerprint {
			continue
		}
		if rec.WrittenAt.Before(cutoff) {
			_ = os.Remove(path)
		}
	}
}
