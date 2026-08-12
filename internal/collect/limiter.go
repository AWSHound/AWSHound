package collect

import "context"

// Limiter bounds the number of concurrent in-flight AWS operations across an
// entire collection run. One Limiter is shared by pointer across every Session
// (all accounts) so the cap spans the full accounts × services × regions fan-out,
// not one account at a time. It is acquired only at leaf work points — each
// region worker in fanRegions and the body of each global collector (IAM, S3,
// Organizations) — which never nest, so the bound cannot deadlock on itself.
//
// A nil *Limiter, or one built with a non-positive cap, is unbounded: acquire and
// release are no-ops. This keeps the default (no --max-concurrency) behaving like
// the original straight fan-out, and lets callers pass nil in tests.
type Limiter struct {
	ch chan struct{}
}

// NewLimiter returns a Limiter that permits at most n concurrent operations. A
// non-positive n yields an unbounded limiter.
func NewLimiter(n int) *Limiter {
	if n <= 0 {
		return &Limiter{}
	}
	return &Limiter{ch: make(chan struct{}, n)}
}

// acquire blocks until a slot is free or ctx is cancelled, returning ctx.Err() in
// the latter case so a cancelled worker can bail without doing work. It is a no-op
// on a nil or unbounded limiter.
func (l *Limiter) acquire(ctx context.Context) error {
	if l == nil || l.ch == nil {
		return nil
	}
	select {
	case l.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// release returns a slot acquired by acquire. It must be paired with each
// successful acquire (typically via defer) and is a no-op on a nil or unbounded
// limiter.
func (l *Limiter) release() {
	if l == nil || l.ch == nil {
		return
	}
	<-l.ch
}
