// Package access is the browser access control of the console process
// (#537): a localhost-only, one-time, short-lived pairing code shown on the
// process's own stdout (container log or terminal), exchanged over a
// same-origin POST for an opaque, server-tracked, read-only browser session
// carried in an HttpOnly cookie. Nothing here is an admin credential: the
// console process has no privileged route, the cookie is meaningless to the
// data-plane server's admin middleware, and no key of any kind travels in a
// URL, in the DOM or in the cookie value.
package access

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"
)

// Pairing errors (machine-readable through the HTTP reason codes in gate.go).
var (
	ErrNoCode        = errors.New("no pairing code has been issued")
	ErrCodeExpired   = errors.New("the pairing code has expired")
	ErrCodeMismatch  = errors.New("the pairing code does not match")
	ErrCodeExhausted = errors.New("the pairing code was voided after too many failed attempts")
	ErrThrottled     = errors.New("too many pairing attempts; wait and retry")
)

// Pairing defaults.
const (
	// DefaultCodeTTL is the longest a code stays valid (#537: at most 10 minutes).
	DefaultCodeTTL = 10 * time.Minute
	// MaxCodeTTL caps a configured TTL.
	MaxCodeTTL = 10 * time.Minute
	// DefaultMaxAttempts voids the current code after this many failed redemptions.
	DefaultMaxAttempts = 5
	// DefaultMinAttemptGap throttles redemption attempts process-wide: the code
	// space is ~98 bits, so this guards the log and the CPU, not the secret.
	DefaultMinAttemptGap = 500 * time.Millisecond

	codeGroups    = 4
	codeGroupSize = 5
	// codeAlphabet omits 0/O, 1/I/L and U so a code read from a terminal or a
	// log survives retyping; 30 symbols × 20 positions ≈ 98 bits.
	codeAlphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
)

// Pairer holds at most one live code. Only its SHA-256 is kept in memory.
type Pairer struct {
	ttl         time.Duration
	maxAttempts int
	minGap      time.Duration
	now         func() time.Time

	mu          sync.Mutex
	codeHash    []byte
	issuedAt    time.Time
	expiresAt   time.Time
	failures    int
	lastAttempt time.Time
}

// NewPairer returns a Pairer with ttl capped at MaxCodeTTL; zero values take
// the defaults.
func NewPairer(ttl time.Duration, maxAttempts int, now func() time.Time) *Pairer {
	if ttl <= 0 || ttl > MaxCodeTTL {
		ttl = DefaultCodeTTL
	}
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Pairer{ttl: ttl, maxAttempts: maxAttempts, minGap: DefaultMinAttemptGap, now: now}
}

// TTL is the validity of a freshly issued code.
func (p *Pairer) TTL() time.Duration { return p.ttl }

// Issue replaces any live code with a fresh one and returns it with its
// expiry. The caller prints it exactly once, to its own trusted output; the
// Pairer never returns it again.
func (p *Pairer) Issue() (code string, expiresAt time.Time, err error) {
	raw := make([]byte, 0, codeGroups*codeGroupSize)
	max := big.NewInt(int64(len(codeAlphabet)))
	for i := 0; i < codeGroups*codeGroupSize; i++ {
		n, rerr := rand.Int(rand.Reader, max)
		if rerr != nil {
			return "", time.Time{}, rerr
		}
		raw = append(raw, codeAlphabet[n.Int64()])
	}
	var groups []string
	for i := 0; i < len(raw); i += codeGroupSize {
		groups = append(groups, string(raw[i:i+codeGroupSize]))
	}
	code = strings.Join(groups, "-")
	sum := sha256.Sum256(raw)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.issuedAt = p.now()
	p.expiresAt = p.issuedAt.Add(p.ttl)
	p.codeHash = sum[:]
	p.failures = 0
	return code, p.expiresAt, nil
}

// ExpiresAt is the expiry of the live code (zero when none).
func (p *Pairer) ExpiresAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.expiresAt
}

// Redeem consumes the live code when presented equals it: a success voids the
// code (single use); a mismatch counts towards maxAttempts, after which the
// code is voided too; attempts closer than the minimum gap are throttled
// without being counted.
func (p *Pairer) Redeem(presented string) error {
	normalized := normalizeCode(presented)
	sum := sha256.Sum256([]byte(normalized))
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if !p.lastAttempt.IsZero() && now.Sub(p.lastAttempt) < p.minGap {
		return ErrThrottled
	}
	p.lastAttempt = now
	if p.codeHash == nil {
		return ErrNoCode
	}
	if now.After(p.expiresAt) {
		p.codeHash = nil
		return ErrCodeExpired
	}
	if subtle.ConstantTimeCompare(sum[:], p.codeHash) != 1 {
		p.failures++
		if p.failures >= p.maxAttempts {
			p.codeHash = nil
			return ErrCodeExhausted
		}
		return ErrCodeMismatch
	}
	p.codeHash = nil // single use
	return nil
}

func normalizeCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(s)) {
		if r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
