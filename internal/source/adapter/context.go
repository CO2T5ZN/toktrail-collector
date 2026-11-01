package adapter

import "context"

// ContextOrBackground returns the option's cancellation scope, falling back
// to context.Background() when the caller left Context nil. Loaders use this
// helper so pre-context callers keep their exact historical behavior: a nil
// Context is an uncancellable background scan, never a panic and never an
// implicit deadline. A loader that supports cancellation checks the returned
// context at coarse scan boundaries and reports ctx.Err() (wrapped with %w
// where a message is added) so callers can match it with
// errors.Is(err, context.Canceled) or errors.Is(err, context.DeadlineExceeded).
func (o Options) ContextOrBackground() context.Context {
	if o.Context == nil {
		return context.Background()
	}
	return o.Context
}
