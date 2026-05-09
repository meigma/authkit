package oidc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/meigma/authkit"
)

const (
	bearerScheme = "Bearer"
	maxJWKSBytes = 1 << 20
)

// Authenticator verifies OIDC-issued JWT bearer tokens from HTTP requests.
type Authenticator struct {
	source ProviderSource

	httpClient      *http.Client
	clock           func() time.Time
	acceptableSkew  time.Duration
	forwardedClaims []authkit.ClaimPath
	keySetCacheTTL  time.Duration

	mu       sync.Mutex
	keySets  map[string]cachedKeySet
	requests map[string]*keySetRequest
}

type cachedKeySet struct {
	set       jwk.Set
	expiresAt time.Time
}

type keySetRequest struct {
	done chan struct{}
	set  jwk.Set
	err  error
}

// NewAuthenticator constructs an OIDC JWT bearer authenticator.
func NewAuthenticator(source ProviderSource, opts ...Option) (*Authenticator, error) {
	if source == nil {
		return nil, errors.New("oidc: provider source is required")
	}

	cfg := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	return &Authenticator{
		source:          source,
		httpClient:      cfg.httpClient,
		clock:           cfg.clock,
		acceptableSkew:  cfg.acceptableSkew,
		forwardedClaims: cloneClaimPaths(cfg.forwardedClaims),
		keySetCacheTTL:  cfg.keySetCacheTTL,
		keySets:         make(map[string]cachedKeySet),
		requests:        make(map[string]*keySetRequest),
	}, nil
}

// Name returns the stable authenticator name.
func (a *Authenticator) Name() string {
	return Name
}

// Authenticate verifies the request's OIDC-issued JWT bearer token.
func (a *Authenticator) Authenticate(ctx context.Context, req *http.Request) (*authkit.Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, unauthenticated("request is required")
	}

	rawToken, err := bearerToken(req)
	if err != nil {
		return nil, err
	}

	issuer, err := unverifiedIssuer(rawToken)
	if err != nil {
		return nil, err
	}

	provider, err := a.source.FindProvider(ctx, issuer)
	if errors.Is(err, ErrProviderNotFound) {
		return nil, unauthenticated("issuer is not trusted")
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: find provider: %w", err)
	}
	if provider.Issuer != issuer {
		return nil, unauthenticated("provider issuer mismatch")
	}
	if validationErr := provider.Validate(); validationErr != nil {
		return nil, fmt.Errorf("oidc: invalid provider: %w", validationErr)
	}

	set, err := a.keySet(ctx, provider)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(
		[]byte(rawToken),
		jwt.WithKeySet(set),
		jwt.WithIssuer(provider.Issuer),
		jwt.WithRequiredClaim(jwt.SubjectKey),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WithClock(jwt.ClockFunc(a.clock)),
		jwt.WithAcceptableSkew(a.acceptableSkew),
	)
	if err != nil {
		return nil, unauthenticated("JWT verification failed")
	}

	subject, ok := token.Subject()
	if !ok || subject == "" {
		return nil, unauthenticated("subject claim is required")
	}
	if !audienceAllowed(token, provider.Audiences) {
		return nil, unauthenticated("audience is not accepted")
	}

	identity := &authkit.Identity{
		Provider: provider.Issuer,
		Subject:  subject,
		Claims:   a.forwardClaims(token, provider),
	}
	if jwtID, ok := token.JwtID(); ok {
		identity.CredentialID = jwtID
	}

	return identity, nil
}

func bearerToken(req *http.Request) (string, error) {
	header := req.Header.Get("Authorization")
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || scheme != bearerScheme || token == "" || strings.Contains(token, " ") {
		return "", unauthenticated("bearer token is required")
	}

	return token, nil
}

func unverifiedIssuer(rawToken string) (string, error) {
	token, err := jwt.ParseInsecure([]byte(rawToken))
	if err != nil {
		return "", unauthenticated("malformed JWT bearer token")
	}

	issuer, ok := token.Issuer()
	if !ok || issuer == "" {
		return "", unauthenticated("issuer claim is required")
	}

	return issuer, nil
}

func audienceAllowed(token jwt.Token, audiences []string) bool {
	tokenAudiences, ok := token.Audience()
	if !ok || len(tokenAudiences) == 0 {
		return false
	}

	accepted := make(map[string]struct{}, len(audiences))
	for _, audience := range audiences {
		accepted[audience] = struct{}{}
	}
	for _, audience := range tokenAudiences {
		if _, ok := accepted[audience]; ok {
			return true
		}
	}

	return false
}

func (a *Authenticator) forwardClaims(token jwt.Token, provider Provider) map[string]any {
	paths := mergedForwardedClaims(provider.ForwardedClaims, a.forwardedClaims)
	if len(paths) == 0 {
		return nil
	}

	claims := make(map[string]any, len(paths))
	for _, path := range paths {
		if !path.Valid() {
			continue
		}

		value, ok := tokenClaim(token, path)
		if ok {
			setClaim(claims, path, value)
		}
	}
	if len(claims) == 0 {
		return nil
	}

	return claims
}

func mergedForwardedClaims(
	providerClaims []authkit.ClaimPath,
	staticClaims []authkit.ClaimPath,
) []authkit.ClaimPath {
	if len(providerClaims) == 0 && len(staticClaims) == 0 {
		return nil
	}

	claims := make([]authkit.ClaimPath, 0, len(providerClaims)+len(staticClaims))
	seen := make(map[string]struct{}, len(providerClaims)+len(staticClaims))
	for _, path := range append(cloneClaimPaths(providerClaims), staticClaims...) {
		key := claimPathKey(path)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}
		claims = append(claims, cloneClaimPath(path))
	}

	return claims
}

func tokenClaim(token jwt.Token, path authkit.ClaimPath) (any, bool) {
	var value any
	if err := token.Get(path[0], &value); err != nil {
		return nil, false
	}
	if len(path) == 1 {
		return cloneClaimValue(value), true
	}

	claimMap := map[string]any{
		path[0]: value,
	}
	resolved, ok := path.Lookup(claimMap)
	if !ok {
		return nil, false
	}

	return cloneClaimValue(resolved), true
}

func setClaim(claims map[string]any, path authkit.ClaimPath, value any) {
	current := claims
	for _, segment := range path[:len(path)-1] {
		next, ok := current[segment].(map[string]any)
		if !ok {
			next = make(map[string]any)
			current[segment] = next
		}
		current = next
	}

	current[path[len(path)-1]] = value
}

func (a *Authenticator) keySet(ctx context.Context, provider Provider) (jwk.Set, error) {
	now := a.clock()
	cacheKey, err := keySetCacheKey(provider)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	if cached, ok := a.keySets[cacheKey]; ok && now.Before(cached.expiresAt) {
		a.mu.Unlock()

		return cached.set, nil
	}
	if req, ok := a.requests[cacheKey]; ok {
		a.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-req.done:
			return req.set, req.err
		}
	}

	req := &keySetRequest{done: make(chan struct{})}
	a.requests[cacheKey] = req
	a.mu.Unlock()

	req.set, req.err = a.fetchKeySet(ctx, provider)

	a.mu.Lock()
	delete(a.requests, cacheKey)
	if req.err == nil && a.keySetCacheTTL > 0 {
		a.keySets[cacheKey] = cachedKeySet{
			set:       req.set,
			expiresAt: now.Add(a.keySetCacheTTL),
		}
	}
	close(req.done)
	a.mu.Unlock()

	return req.set, req.err
}

func keySetCacheKey(provider Provider) (string, error) {
	algorithms, err := provider.signingAlgorithms()
	if err != nil {
		return "", err
	}

	names := make([]string, len(algorithms))
	for i, algorithm := range algorithms {
		names[i] = algorithm.String()
	}

	return provider.JWKSURL + "\x00" + strings.Join(names, ","), nil
}

func (a *Authenticator) fetchKeySet(ctx context.Context, provider Provider) (jwk.Set, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.JWKSURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: create JWKS request: %w", err)
	}

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("oidc: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxJWKSBytes))

		return nil, fmt.Errorf("oidc: fetch JWKS: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return nil, fmt.Errorf("oidc: read JWKS: %w", err)
	}

	set, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("oidc: parse JWKS: %w", err)
	}

	constrained, err := constrainKeySet(set, provider)
	if err != nil {
		return nil, err
	}

	return constrained, nil
}

func constrainKeySet(set jwk.Set, provider Provider) (jwk.Set, error) {
	allowed, err := provider.signingAlgorithms()
	if err != nil {
		return nil, err
	}

	allowedByName := make(map[string]jwa.SignatureAlgorithm, len(allowed))
	for _, algorithm := range allowed {
		allowedByName[algorithm.String()] = algorithm
	}

	constrained := jwk.NewSet()
	for i := range set.Len() {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		publicKey, ok, err := verificationKey(key, allowed, allowedByName)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if err := constrained.AddKey(publicKey); err != nil {
			return nil, fmt.Errorf("oidc: add JWKS key: %w", err)
		}
	}
	if constrained.Len() == 0 {
		return nil, errors.New("oidc: JWKS contained no usable signing keys")
	}

	return constrained, nil
}

func verificationKey(
	key jwk.Key,
	allowed []jwa.SignatureAlgorithm,
	allowedByName map[string]jwa.SignatureAlgorithm,
) (jwk.Key, bool, error) {
	key, err := key.Clone()
	if err != nil {
		return nil, false, fmt.Errorf("oidc: clone JWKS key: %w", err)
	}
	if !keyAllowsVerification(key) {
		return nil, false, nil
	}

	algorithm, ok := key.Algorithm()
	switch {
	case ok:
		if _, allowed := allowedByName[algorithm.String()]; !allowed {
			return nil, false, nil
		}
	case len(allowed) == 1:
		if setErr := key.Set(jwk.AlgorithmKey, allowed[0]); setErr != nil {
			return nil, false, fmt.Errorf("oidc: set JWKS key algorithm: %w", setErr)
		}
	default:
		return nil, false, nil
	}

	publicKey, err := key.PublicKey()
	if err != nil {
		return nil, false, fmt.Errorf("oidc: convert JWKS key to public key: %w", err)
	}

	return publicKey, true, nil
}

func keyAllowsVerification(key jwk.Key) bool {
	if usage, ok := key.KeyUsage(); ok && usage != jwk.ForSignature.String() {
		return false
	}

	ops, ok := key.KeyOps()
	if !ok {
		return true
	}

	return slices.Contains(ops, jwk.KeyOpVerify)
}

func unauthenticated(reason string) error {
	return fmt.Errorf("%w: %s", authkit.ErrUnauthenticated, reason)
}
