package httpauth

type options struct {
	renderer ErrorRenderer
}

// Option configures Middleware.
type Option func(*options)

func defaultOptions() options {
	return options{
		renderer: defaultErrorRenderer,
	}
}

// WithErrorRenderer configures the renderer used for auth failures.
func WithErrorRenderer(renderer ErrorRenderer) Option {
	return func(opts *options) {
		opts.renderer = renderer
	}
}
