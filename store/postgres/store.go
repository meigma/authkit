package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/apikey"
	"github.com/meigma/authkit/oidc"
)

const (
	foreignKeyViolation = "23503"
	principalIDAttempts = 3
	principalIDPrefix   = "principal_"
	uniqueViolation     = "23505"
)

// Store persists authkit principals, identity links, API tokens, and OIDC provider trust in PostgreSQL.
type Store struct {
	pool *pgxpool.Pool
}

type sqlExecutor interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// NewStore constructs a PostgreSQL store around pool.
func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("postgres: pool is required")
	}

	return &Store{
		pool: pool,
	}, nil
}

// CreatePrincipal creates a principal in PostgreSQL.
func (s *Store) CreatePrincipal(
	ctx context.Context,
	req authkit.CreatePrincipalRequest,
) (authkit.Principal, error) {
	if err := ctx.Err(); err != nil {
		return authkit.Principal{}, err
	}
	if req.Kind != authkit.PrincipalKindUser && req.Kind != authkit.PrincipalKindService {
		return authkit.Principal{}, fmt.Errorf("postgres: unsupported principal kind %q", req.Kind)
	}

	return createPrincipal(ctx, s.pool, req)
}

func createPrincipal(
	ctx context.Context,
	exec sqlExecutor,
	req authkit.CreatePrincipalRequest,
) (authkit.Principal, error) {
	attributes, err := encodeAttributes(req.Attributes)
	if err != nil {
		return authkit.Principal{}, err
	}

	for range principalIDAttempts {
		principal := authkit.Principal{
			ID:          principalIDPrefix + rand.Text(),
			Kind:        req.Kind,
			DisplayName: req.DisplayName,
			Attributes:  cloneAttributes(req.Attributes),
		}
		_, err := exec.Exec(
			ctx,
			`insert into authkit_principals (id, kind, display_name, attributes)
			values ($1, $2, $3, nullif($4, '')::jsonb)`,
			principal.ID,
			string(principal.Kind),
			principal.DisplayName,
			attributes,
		)
		if err == nil {
			return principal, nil
		}
		if !isPostgresCode(err, uniqueViolation) {
			return authkit.Principal{}, fmt.Errorf("postgres: create principal: %w", err)
		}
	}

	return authkit.Principal{}, errors.New("postgres: create principal: generated duplicate principal IDs")
}

// LinkIdentity links an external identity to an existing principal.
func (s *Store) LinkIdentity(
	ctx context.Context,
	req authkit.LinkIdentityRequest,
) (authkit.ExternalIdentity, error) {
	if err := ctx.Err(); err != nil {
		return authkit.ExternalIdentity{}, err
	}
	if req.Provider == "" {
		return authkit.ExternalIdentity{}, errors.New("postgres: provider is required")
	}
	if req.Subject == "" {
		return authkit.ExternalIdentity{}, errors.New("postgres: subject is required")
	}
	if req.PrincipalID == "" {
		return authkit.ExternalIdentity{}, errors.New("postgres: principal ID is required")
	}

	link, err := s.findIdentityLink(ctx, req.Provider, req.Subject)
	if err == nil {
		if link.PrincipalID == req.PrincipalID {
			return link, nil
		}

		return authkit.ExternalIdentity{}, fmt.Errorf(
			"postgres: identity %q/%q is already linked to principal %q",
			req.Provider,
			req.Subject,
			link.PrincipalID,
		)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return authkit.ExternalIdentity{}, fmt.Errorf("postgres: find identity link: %w", err)
	}

	link = authkit.ExternalIdentity(req)
	if _, err := s.pool.Exec(
		ctx,
		`insert into authkit_external_identities (provider, subject, principal_id)
		values ($1, $2, $3)`,
		link.Provider,
		link.Subject,
		link.PrincipalID,
	); err != nil {
		if isPostgresCode(err, uniqueViolation) {
			return s.resolveIdentityLinkConflict(ctx, req)
		}
		if isPostgresCode(err, foreignKeyViolation) {
			return authkit.ExternalIdentity{}, fmt.Errorf(
				"postgres: principal %q does not exist",
				req.PrincipalID,
			)
		}

		return authkit.ExternalIdentity{}, fmt.Errorf("postgres: link identity: %w", err)
	}

	return link, nil
}

// ResolveIdentity returns the principal linked to identity.
func (s *Store) ResolveIdentity(
	ctx context.Context,
	identity authkit.Identity,
) (*authkit.Principal, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if identity.Provider == "" || identity.Subject == "" {
		return nil, fmt.Errorf("%w: provider and subject are required", authkit.ErrUnresolvedIdentity)
	}

	var principal authkit.Principal
	var kind string
	var attributes string
	err := s.pool.QueryRow(
		ctx,
		`select p.id, p.kind, p.display_name, coalesce(p.attributes::text, '')
		from authkit_external_identities as i
		join authkit_principals as p on p.id = i.principal_id
		where i.provider = $1 and i.subject = $2`,
		identity.Provider,
		identity.Subject,
	).Scan(&principal.ID, &kind, &principal.DisplayName, &attributes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf(
			"%w: identity %q/%q is not linked",
			authkit.ErrUnresolvedIdentity,
			identity.Provider,
			identity.Subject,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: resolve identity: %w", err)
	}

	principal.Kind = authkit.PrincipalKind(kind)
	principal.Attributes, err = decodeAttributes(attributes)
	if err != nil {
		return nil, err
	}

	return &principal, nil
}

// ProvisionIdentity creates and links a principal for identity or returns the existing link.
func (s *Store) ProvisionIdentity(
	ctx context.Context,
	req authkit.ProvisionIdentityRequest,
) (authkit.ProvisionIdentityResult, error) {
	if err := ctx.Err(); err != nil {
		return authkit.ProvisionIdentityResult{}, err
	}
	if req.Identity.Provider == "" || req.Identity.Subject == "" {
		return authkit.ProvisionIdentityResult{}, fmt.Errorf(
			"%w: provider and subject are required",
			authkit.ErrUnresolvedIdentity,
		)
	}
	if req.Principal.Kind != authkit.PrincipalKindUser && req.Principal.Kind != authkit.PrincipalKindService {
		return authkit.ProvisionIdentityResult{}, fmt.Errorf(
			"postgres: unsupported principal kind %q",
			req.Principal.Kind,
		)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return authkit.ProvisionIdentityResult{}, fmt.Errorf("postgres: begin provision identity: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	existing, err := findProvisionedIdentity(ctx, tx, req.Identity)
	if err == nil {
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return authkit.ProvisionIdentityResult{}, fmt.Errorf("postgres: commit provision identity: %w", commitErr)
		}

		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return authkit.ProvisionIdentityResult{}, fmt.Errorf("postgres: find provisioned identity: %w", err)
	}

	principal, err := createPrincipal(ctx, tx, req.Principal)
	if err != nil {
		return authkit.ProvisionIdentityResult{}, err
	}

	link := authkit.ExternalIdentity{
		Provider:    req.Identity.Provider,
		Subject:     req.Identity.Subject,
		PrincipalID: principal.ID,
	}
	if _, err := tx.Exec(
		ctx,
		`insert into authkit_external_identities (provider, subject, principal_id)
		values ($1, $2, $3)`,
		link.Provider,
		link.Subject,
		link.PrincipalID,
	); err != nil {
		return s.handleProvisionIdentityLinkError(ctx, tx, req.Identity, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return authkit.ProvisionIdentityResult{}, fmt.Errorf("postgres: commit provision identity: %w", err)
	}

	return authkit.ProvisionIdentityResult{
		Principal: principal,
		Link:      link,
		Created:   true,
	}, nil
}

func (s *Store) handleProvisionIdentityLinkError(
	ctx context.Context,
	tx pgx.Tx,
	identity authkit.Identity,
	err error,
) (authkit.ProvisionIdentityResult, error) {
	if !isPostgresCode(err, uniqueViolation) {
		return authkit.ProvisionIdentityResult{}, fmt.Errorf("postgres: link provisioned identity: %w", err)
	}
	if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
		return authkit.ProvisionIdentityResult{}, fmt.Errorf(
			"postgres: rollback provision identity conflict: %w",
			rollbackErr,
		)
	}

	winner, findErr := findProvisionedIdentity(ctx, s.pool, identity)
	if findErr != nil {
		return authkit.ProvisionIdentityResult{}, fmt.Errorf(
			"postgres: find provisioned identity conflict: %w",
			findErr,
		)
	}

	return winner, nil
}

// CreateToken stores token.
func (s *Store) CreateToken(ctx context.Context, token apikey.StoredToken) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if token.ID == "" {
		return errors.New("postgres: token ID is required")
	}

	if _, err := s.pool.Exec(
		ctx,
		`insert into authkit_api_tokens
			(id, principal_id, name, secret_hash, expires_at, last_used_at, revoked_at)
		values ($1, $2, $3, $4, $5, $6, $7)`,
		token.ID,
		token.PrincipalID,
		token.Name,
		token.SecretHash[:],
		token.ExpiresAt,
		token.LastUsedAt,
		token.RevokedAt,
	); err != nil {
		if isPostgresCode(err, foreignKeyViolation) {
			return fmt.Errorf("postgres: principal %q does not exist", token.PrincipalID)
		}

		return fmt.Errorf("postgres: create token: %w", err)
	}

	return nil
}

// FindToken returns the token for tokenID.
func (s *Store) FindToken(ctx context.Context, tokenID string) (apikey.StoredToken, error) {
	if err := ctx.Err(); err != nil {
		return apikey.StoredToken{}, err
	}

	token, err := s.findToken(ctx, tokenID)
	if errors.Is(err, pgx.ErrNoRows) {
		return apikey.StoredToken{}, apikey.ErrTokenNotFound
	}
	if err != nil {
		return apikey.StoredToken{}, err
	}

	return token, nil
}

// UpdateTokenLastUsed records the most recent successful use of tokenID.
func (s *Store) UpdateTokenLastUsed(ctx context.Context, tokenID string, usedAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	tag, err := s.pool.Exec(
		ctx,
		`update authkit_api_tokens set last_used_at = $2 where id = $1`,
		tokenID,
		usedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: update token last used: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return apikey.ErrTokenNotFound
	}

	return nil
}

// RevokeToken records tokenID as revoked.
func (s *Store) RevokeToken(ctx context.Context, tokenID string, revokedAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	tag, err := s.pool.Exec(
		ctx,
		`update authkit_api_tokens set revoked_at = $2 where id = $1`,
		tokenID,
		revokedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: revoke token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return apikey.ErrTokenNotFound
	}

	return nil
}

// TrustProvider stores provider as trusted for its issuer.
func (s *Store) TrustProvider(ctx context.Context, provider oidc.Provider) (oidc.Provider, error) {
	if err := ctx.Err(); err != nil {
		return oidc.Provider{}, err
	}
	if err := provider.Validate(); err != nil {
		return oidc.Provider{}, err
	}

	trusted := cloneProvider(provider)
	signingAlgorithms := trusted.SupportedSigningAlgorithms
	if signingAlgorithms == nil {
		signingAlgorithms = []string{}
	}
	if _, err := s.pool.Exec(
		ctx,
		`insert into authkit_oidc_providers
			(issuer, jwks_url, audiences, supported_signing_algorithms)
		values ($1, $2, $3, $4)
		on conflict (issuer) do update set
			jwks_url = excluded.jwks_url,
			audiences = excluded.audiences,
			supported_signing_algorithms = excluded.supported_signing_algorithms,
			updated_at = now()`,
		trusted.Issuer,
		trusted.JWKSURL,
		trusted.Audiences,
		signingAlgorithms,
	); err != nil {
		return oidc.Provider{}, fmt.Errorf("postgres: trust OIDC provider: %w", err)
	}

	return cloneProvider(trusted), nil
}

// FindProvider returns the trusted OIDC provider for issuer.
func (s *Store) FindProvider(ctx context.Context, issuer string) (oidc.Provider, error) {
	if err := ctx.Err(); err != nil {
		return oidc.Provider{}, err
	}

	var provider oidc.Provider
	err := s.pool.QueryRow(
		ctx,
		`select issuer, audiences, jwks_url, supported_signing_algorithms
		from authkit_oidc_providers
		where issuer = $1`,
		issuer,
	).Scan(
		&provider.Issuer,
		&provider.Audiences,
		&provider.JWKSURL,
		&provider.SupportedSigningAlgorithms,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return oidc.Provider{}, oidc.ErrProviderNotFound
	}
	if err != nil {
		return oidc.Provider{}, fmt.Errorf("postgres: find OIDC provider: %w", err)
	}
	if err := provider.Validate(); err != nil {
		return oidc.Provider{}, fmt.Errorf("postgres: invalid OIDC provider %q: %w", issuer, err)
	}

	return cloneProvider(provider), nil
}

func (s *Store) findIdentityLink(
	ctx context.Context,
	provider string,
	subject string,
) (authkit.ExternalIdentity, error) {
	var link authkit.ExternalIdentity
	err := s.pool.QueryRow(
		ctx,
		`select provider, subject, principal_id
		from authkit_external_identities
		where provider = $1 and subject = $2`,
		provider,
		subject,
	).Scan(&link.Provider, &link.Subject, &link.PrincipalID)
	if err != nil {
		return authkit.ExternalIdentity{}, err
	}

	return link, nil
}

func findProvisionedIdentity(
	ctx context.Context,
	query rowQuerier,
	identity authkit.Identity,
) (authkit.ProvisionIdentityResult, error) {
	var principal authkit.Principal
	var kind string
	var attributes string
	var link authkit.ExternalIdentity
	err := query.QueryRow(
		ctx,
		`select p.id, p.kind, p.display_name, coalesce(p.attributes::text, ''),
			i.provider, i.subject, i.principal_id
		from authkit_external_identities as i
		join authkit_principals as p on p.id = i.principal_id
		where i.provider = $1 and i.subject = $2`,
		identity.Provider,
		identity.Subject,
	).Scan(
		&principal.ID,
		&kind,
		&principal.DisplayName,
		&attributes,
		&link.Provider,
		&link.Subject,
		&link.PrincipalID,
	)
	if err != nil {
		return authkit.ProvisionIdentityResult{}, err
	}

	principal.Kind = authkit.PrincipalKind(kind)
	principal.Attributes, err = decodeAttributes(attributes)
	if err != nil {
		return authkit.ProvisionIdentityResult{}, err
	}

	return authkit.ProvisionIdentityResult{
		Principal: principal,
		Link:      link,
		Created:   false,
	}, nil
}

func (s *Store) resolveIdentityLinkConflict(
	ctx context.Context,
	req authkit.LinkIdentityRequest,
) (authkit.ExternalIdentity, error) {
	link, err := s.findIdentityLink(ctx, req.Provider, req.Subject)
	if err != nil {
		return authkit.ExternalIdentity{}, fmt.Errorf("postgres: find identity link conflict: %w", err)
	}
	if link.PrincipalID == req.PrincipalID {
		return link, nil
	}

	return authkit.ExternalIdentity{}, fmt.Errorf(
		"postgres: identity %q/%q is already linked to principal %q",
		req.Provider,
		req.Subject,
		link.PrincipalID,
	)
}

func (s *Store) findToken(ctx context.Context, tokenID string) (apikey.StoredToken, error) {
	var token apikey.StoredToken
	var secretHash []byte
	var lastUsedAt pgtype.Timestamptz
	var revokedAt pgtype.Timestamptz
	err := s.pool.QueryRow(
		ctx,
		`select id, principal_id, name, secret_hash, expires_at, last_used_at, revoked_at
		from authkit_api_tokens
		where id = $1`,
		tokenID,
	).Scan(
		&token.ID,
		&token.PrincipalID,
		&token.Name,
		&secretHash,
		&token.ExpiresAt,
		&lastUsedAt,
		&revokedAt,
	)
	if err != nil {
		return apikey.StoredToken{}, err
	}
	if len(secretHash) != sha256.Size {
		return apikey.StoredToken{}, fmt.Errorf(
			"postgres: token %q has invalid secret hash length %d",
			tokenID,
			len(secretHash),
		)
	}

	copy(token.SecretHash[:], secretHash)
	token.ExpiresAt = token.ExpiresAt.UTC()
	token.LastUsedAt = timeFromTimestamptz(lastUsedAt)
	token.RevokedAt = timeFromTimestamptz(revokedAt)

	return token, nil
}

func encodeAttributes(attrs map[string]any) (string, error) {
	if len(attrs) == 0 {
		return "", nil
	}

	encoded, err := json.Marshal(attrs)
	if err != nil {
		return "", fmt.Errorf("postgres: encode principal attributes: %w", err)
	}

	return string(encoded), nil
}

func decodeAttributes(encoded string) (map[string]any, error) {
	if encoded == "" || encoded == "null" {
		//nolint:nilnil // Nil attributes are the normalized zero value for principals.
		return nil, nil
	}

	var attrs map[string]any
	if err := json.Unmarshal([]byte(encoded), &attrs); err != nil {
		return nil, fmt.Errorf("postgres: decode principal attributes: %w", err)
	}
	if len(attrs) == 0 {
		//nolint:nilnil // Nil attributes are the normalized zero value for principals.
		return nil, nil
	}

	return attrs, nil
}

func cloneAttributes(attrs map[string]any) map[string]any {
	if len(attrs) == 0 {
		return nil
	}

	cloned := make(map[string]any, len(attrs))
	maps.Copy(cloned, attrs)

	return cloned
}

func cloneProvider(provider oidc.Provider) oidc.Provider {
	provider.Audiences = cloneStrings(provider.Audiences)
	provider.SupportedSigningAlgorithms = cloneStrings(provider.SupportedSigningAlgorithms)

	return provider
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	cloned := make([]string, len(values))
	copy(cloned, values)

	return cloned
}

func timeFromTimestamptz(value pgtype.Timestamptz) *time.Time {
	if !value.Valid {
		return nil
	}

	t := value.Time.UTC()

	return &t
}

func isPostgresCode(err error, code string) bool {
	var pgErr *pgconn.PgError

	return errors.As(err, &pgErr) && pgErr.Code == code
}
