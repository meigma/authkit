package casbin

// Option configures an Authorizer.
type Option func(*options)

type options struct {
	requestBuilder RequestBuilder
}

func defaultOptions() options {
	return options{
		requestBuilder: DefaultRequestBuilder,
	}
}

// WithRequestBuilder configures how authkit authorization inputs become Casbin request values.
func WithRequestBuilder(builder RequestBuilder) Option {
	return func(opts *options) {
		if builder != nil {
			opts.requestBuilder = builder
		}
	}
}
