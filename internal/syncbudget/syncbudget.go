// Package syncbudget bounds the attempts a single run may make with one
// counter shared by every goroutine of that run. Workers call
// Reserve(ctx, queue) before starting an attempt; the call atomically
// decides between granting the attempt (spending one unit of the run-wide
// total and of the queue's own cap, when present) and declining it with an
// explicit reason. Concurrent callers can never collectively exceed any
// configured cap: the whole decision happens under one lock hold.
//
// The budget is deliberately small in scope. It never blocks, never waits,
// never retries, and never starts goroutines, timers, or network activity.
// Its deadline is lazy: nothing wakes up when the deadline passes, but
// every later Reserve declines with ErrDeadlineExceeded. Waiting,
// retrying, and reacting to a decline are caller-owned decisions, and
// context cancellation always flows in from the caller — the budget never
// creates a context of its own. There is also no refund: an attempt, once
// reserved, is spent for the lifetime of the budget, because the runs this
// package serves stop on the first decline instead of retrying within the
// same run.
//
// A nil *Budget is a valid unlimited budget. Every method works on the nil
// receiver, so callers can thread an optional budget straight through
// without nil checks; on nil, Reserve still honors the caller's context
// cancellation, but no usage is tracked. Unlimited budgets are reported
// distinctly from spent ones: Remaining and QueueRemaining return
// (n int, ok bool) where ok=false means "no cap exists" (n is then 0 and
// meaningless) and ok=true with n==0 means "the cap is exhausted — or was
// an explicit zero cap". That bool is what keeps an unlimited budget from
// being confused with a zero or exhausted one; New(WithTotal(0)) is a
// budget that allows nothing, never an unlimited one.
package syncbudget

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Reasons Reserve reports when it declines an attempt. They are sentinels,
// compared with errors.Is; Reserve returns them unwrapped so callers can
// branch on them directly. Add call-site context (such as the queue name)
// by wrapping with %w where a log line needs it.
var (
	// ErrTotalExhausted means the run-wide attempt cap is fully spent, so
	// no queue may start anything more.
	ErrTotalExhausted = errors.New("syncbudget: total attempt budget exhausted")

	// ErrQueueExhausted means this queue's own attempt cap is fully spent
	// while the run-wide budget may still have room for other queues.
	ErrQueueExhausted = errors.New("syncbudget: queue attempt budget exhausted")

	// ErrDeadlineExceeded means the budget's own absolute deadline (see
	// WithDeadline) is no longer strictly in the future. It wraps
	// context.DeadlineExceeded so a caller can treat every time-based stop
	// uniformly, while errors.Is(err, ErrDeadlineExceeded) still separates
	// a budget deadline from the caller's own context deadline.
	ErrDeadlineExceeded = fmt.Errorf("syncbudget: budget deadline exceeded: %w", context.DeadlineExceeded)
)

// Option is one configuration step for New. Options apply in order; when
// two options set the same field, the later one wins. The unexported
// config parameter keeps outside code from forging arbitrary Options.
type Option func(*config)

// config is the pre-construction form of a Budget.
type config struct {
	now         func() time.Time
	deadline    time.Time
	hasDeadline bool
	total       int
	totalSet    bool
	queueCaps   map[string]int
}

// WithTotal caps the total number of attempts across all queues at n.
// Omitting the option leaves the run uncapped. n must be 0 or positive:
// 0 is an explicit zero budget that grants nothing (and is reported as
// exhausted, not as unlimited), which stays distinguishable from both a
// nil budget and an option-less New via Remaining's ok flag. Panics on a
// negative n.
func WithTotal(n int) Option {
	if n < 0 {
		panic(fmt.Sprintf("syncbudget: WithTotal requires a cap of 0 or more, got %d", n))
	}
	return func(c *config) {
		c.total = n
		c.totalSet = true
	}
}

// WithQueueCap caps the attempts of one queue at n. A queue that gets no
// WithQueueCap has no cap of its own and is bounded only by the run-wide
// total. Queue names are matched exactly — no trimming, no case folding —
// so the strings passed here and to Reserve must agree byte for byte. n
// must be 0 or positive (0 blocks that queue outright). Panics on an
// empty queue name or a negative n. A later WithQueueCap for the same
// queue replaces an earlier one.
func WithQueueCap(queue string, n int) Option {
	if queue == "" {
		panic("syncbudget: WithQueueCap requires a non-empty queue name")
	}
	if n < 0 {
		panic(fmt.Sprintf("syncbudget: WithQueueCap requires a cap of 0 or more for queue %q, got %d", queue, n))
	}
	return func(c *config) {
		if c.queueCaps == nil {
			c.queueCaps = make(map[string]int)
		}
		c.queueCaps[queue] = n
	}
}

// WithDeadline sets an absolute deadline: Reserve grants an attempt only
// strictly before this time. The deadline is evaluated lazily on each
// Reserve (nothing ticks in the background), and the usage queries ignore
// it — they report counters, not expiry. Omitting the option means no
// deadline. The zero time is rejected (it would ambiguously read as
// "already expired") — pass a real time or no deadline at all. A later
// WithDeadline replaces an earlier one.
func WithDeadline(deadline time.Time) Option {
	if deadline.IsZero() {
		panic("syncbudget: WithDeadline requires a non-zero deadline (omit the option for no deadline)")
	}
	return func(c *config) {
		c.deadline = deadline
		c.hasDeadline = true
	}
}

// WithNow overrides the clock the budget consults for its deadline, for
// tests. The function must be safe for concurrent use and must not call
// back into the same Budget (Reserve invokes it while holding the budget's
// internal lock). Defaults to time.Now. Panics on nil. A later WithNow
// replaces an earlier one.
func WithNow(now func() time.Time) Option {
	if now == nil {
		panic("syncbudget: WithNow requires a non-nil clock function")
	}
	return func(c *config) { c.now = now }
}

// Budget is a per-run attempt budget shared across goroutines. All methods
// are safe for concurrent use and on a nil receiver, where the budget is
// unlimited and untracked. Build one with New; do not copy a non-nil
// Budget (the copy would race on the shared counters with the original).
type Budget struct {
	now         func() time.Time
	deadline    time.Time
	hasDeadline bool

	mu       sync.Mutex
	total    int
	totalSet bool
	// totalUsed counts granted attempts across all queues. It only ever
	// grows: declines consume nothing and there is no refund.
	totalUsed int
	// queueCaps holds the per-queue caps. A queue absent from the map has
	// no cap of its own and is bounded only by the total.
	queueCaps map[string]int
	// queueUsed counts granted attempts for every queue that has ever
	// reserved, capped or not, so QueueUsed reports real numbers for
	// uncapped queues too.
	queueUsed map[string]int
}

// New builds a shared budget. With no options the budget is unlimited but
// still counts usage; a nil *Budget is unlimited and counts nothing. See
// the Option constructors for validation rules (invalid arguments panic,
// surfacing programmer error at startup instead of mid-run).
func New(opts ...Option) *Budget {
	cfg := config{now: time.Now}
	for _, opt := range opts {
		if opt == nil {
			panic("syncbudget: New received a nil Option")
		}
		opt(&cfg)
	}
	return &Budget{
		now:         cfg.now,
		deadline:    cfg.deadline,
		hasDeadline: cfg.hasDeadline,
		total:       cfg.total,
		totalSet:    cfg.totalSet,
		queueCaps:   cfg.queueCaps,
		queueUsed:   make(map[string]int),
	}
}

// Reserve atomically reserves one attempt for queue. It returns nil when
// the attempt is granted. When it declines, it returns exactly one of, in
// this order of checks:
//
//   - the caller's context error, when ctx is already done (checked
//     first, so a canceled run never spends budget even if some remains);
//   - ErrDeadlineExceeded, when the budget's deadline is reached;
//   - ErrTotalExhausted, when the run-wide cap is spent;
//   - ErrQueueExhausted, when this queue's own cap is spent.
//
// The total is checked before the queue cap so that when both are spent,
// the stronger, run-wide stop reason is reported. A decline never consumes
// anything: counters move only on a grant, and the grant decision —
// deadline, total, queue cap, increments — happens inside one lock hold,
// so concurrent callers cannot collectively exceed any cap. Reserve never
// blocks and never retries.
//
// The queue name must be non-empty and is matched exactly; Reserve panics
// on an empty name because granting under an unnamed key would silently
// corrupt accounting.
func (b *Budget) Reserve(ctx context.Context, queue string) error {
	if queue == "" {
		panic("syncbudget: Reserve requires a non-empty queue name")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.hasDeadline && !b.now().Before(b.deadline) {
		return ErrDeadlineExceeded
	}
	if b.totalSet && b.totalUsed >= b.total {
		return ErrTotalExhausted
	}
	if queueCap, capped := b.queueCaps[queue]; capped && b.queueUsed[queue] >= queueCap {
		return ErrQueueExhausted
	}
	b.totalUsed++
	b.queueUsed[queue]++
	return nil
}

// Used reports the attempts granted across all queues so far. On a nil
// budget nothing is tracked, so Used reports 0.
func (b *Budget) Used() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.totalUsed
}

// Remaining reports the attempts left under the run-wide cap. ok is false
// when the budget has no total cap — n is then 0 and meaningless — and
// true when a cap exists, including the exhausted and explicit zero-cap
// cases (n == 0). The ok flag is what keeps "unlimited" distinguishable
// from "nothing left". The count ignores the deadline: a budget can be
// expired and still report remaining attempts.
func (b *Budget) Remaining() (n int, ok bool) {
	if b == nil {
		return 0, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.totalSet {
		return 0, false
	}
	return b.total - b.totalUsed, true
}

// QueueUsed reports the attempts granted for queue so far: 0 for queues
// that never reserved, and always 0 on a nil budget.
func (b *Budget) QueueUsed(queue string) int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.queueUsed[queue]
}

// QueueRemaining reports the attempts left under queue's own cap. ok is
// false when the queue has no cap of its own — even when the run-wide
// budget is capped. The effective allowance for a queue is the minimum of
// its own remaining and the run-wide remaining, which the caller computes
// from the two queries.
func (b *Budget) QueueRemaining(queue string) (n int, ok bool) {
	if b == nil {
		return 0, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	queueCap, capped := b.queueCaps[queue]
	if !capped {
		return 0, false
	}
	return queueCap - b.queueUsed[queue], true
}
