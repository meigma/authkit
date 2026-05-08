package apikey

import "time"

// Option configures a Service.
type Option func(*options)

type options struct {
	clock func() time.Time
}

func defaultOptions() options {
	return options{
		clock: time.Now,
	}
}

// WithClock configures the clock used for token timestamps.
func WithClock(clock func() time.Time) Option {
	return func(opts *options) {
		if clock != nil {
			opts.clock = clock
		}
	}
}
