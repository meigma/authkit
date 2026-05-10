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
	"github.com/meigma/authkit/provisioning"
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

type queryExecutor interface {
	sqlExecutor
	rowQuerier
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

type scanner interface {
	Scan(dest ...any) error
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

// CreateRole creates a local role in PostgreSQL.
func (s *Store) CreateRole(ctx context.Context, req authkit.CreateRoleRequest) (authkit.Role, error) {
	if err := ctx.Err(); err != nil {
		return authkit.Role{}, err
	}
	if req.ID == "" {
		return authkit.Role{}, errors.New("postgres: role ID is required")
	}

	role := authkit.Role(req)
	if _, err := s.pool.Exec(
		ctx,
		`insert into authkit_roles (id, display_name, description)
		values ($1, $2, $3)`,
		role.ID,
		role.DisplayName,
		role.Description,
	); err != nil {
		if isPostgresCode(err, uniqueViolation) {
			return authkit.Role{}, fmt.Errorf("postgres: role %q already exists", req.ID)
		}

		return authkit.Role{}, fmt.Errorf("postgres: create role: %w", err)
	}

	return role, nil
}

// GrantRoleAction grants an action to a local role.
func (s *Store) GrantRoleAction(ctx context.Context, req authkit.GrantRoleActionRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.RoleID == "" {
		return errors.New("postgres: role ID is required")
	}
	if req.Action == "" {
		return errors.New("postgres: action is required")
	}

	if _, err := s.pool.Exec(
		ctx,
		`insert into authkit_role_actions (role_id, action)
		values ($1, $2)
		on conflict (role_id, action) do nothing`,
		req.RoleID,
		req.Action,
	); err != nil {
		if isPostgresCode(err, foreignKeyViolation) {
			return fmt.Errorf("postgres: role %q does not exist", req.RoleID)
		}

		return fmt.Errorf("postgres: grant role action: %w", err)
	}

	return nil
}

// AssignPrincipalRole assigns a principal to a local role.
func (s *Store) AssignPrincipalRole(ctx context.Context, req authkit.AssignPrincipalRoleRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.PrincipalID == "" {
		return errors.New("postgres: principal ID is required")
	}
	if req.RoleID == "" {
		return errors.New("postgres: role ID is required")
	}

	if _, err := s.pool.Exec(
		ctx,
		`insert into authkit_principal_roles (principal_id, role_id)
		values ($1, $2)
		on conflict (principal_id, role_id) do nothing`,
		req.PrincipalID,
		req.RoleID,
	); err != nil {
		if isPostgresCode(err, foreignKeyViolation) {
			return fmt.Errorf(
				"postgres: principal %q or role %q does not exist",
				req.PrincipalID,
				req.RoleID,
			)
		}

		return fmt.Errorf("postgres: assign principal role: %w", err)
	}

	return nil
}

// ResolvePrincipalActions returns the distinct actions granted to principalID through roles.
func (s *Store) ResolvePrincipalActions(ctx context.Context, principalID string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if principalID == "" {
		return nil, errors.New("postgres: principal ID is required")
	}

	exists, err := s.principalExists(ctx, principalID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("postgres: principal %q does not exist", principalID)
	}

	rows, err := s.pool.Query(
		ctx,
		`select distinct ra.action
		from authkit_principal_roles as pr
		join authkit_role_actions as ra on ra.role_id = pr.role_id
		where pr.principal_id = $1
		order by ra.action`,
		principalID,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres: resolve principal actions: %w", err)
	}
	defer rows.Close()

	var actions []string
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			return nil, fmt.Errorf("postgres: scan principal action: %w", err)
		}
		actions = append(actions, action)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: read principal actions: %w", err)
	}

	return actions, nil
}

// CreateProvisioningRule creates a provisioning rule in PostgreSQL.
func (s *Store) CreateProvisioningRule(
	ctx context.Context,
	req authkit.CreateProvisioningRuleRequest,
) (authkit.ProvisioningRule, error) {
	if err := ctx.Err(); err != nil {
		return authkit.ProvisioningRule{}, err
	}

	rule := provisioningRuleFromCreate(req)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return authkit.ProvisioningRule{}, fmt.Errorf("postgres: begin create provisioning rule: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if validationErr := validateProvisioningRule(ctx, tx, rule); validationErr != nil {
		return authkit.ProvisioningRule{}, validationErr
	}
	if err := insertProvisioningRule(ctx, tx, rule); err != nil {
		return authkit.ProvisioningRule{}, err
	}
	if err := insertProvisioningRuleRoles(ctx, tx, rule.ID, rule.AssignRoleIDs); err != nil {
		return authkit.ProvisioningRule{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return authkit.ProvisioningRule{}, fmt.Errorf("postgres: commit create provisioning rule: %w", err)
	}

	return cloneProvisioningRule(rule), nil
}

// UpdateProvisioningRule replaces a provisioning rule in PostgreSQL.
func (s *Store) UpdateProvisioningRule(
	ctx context.Context,
	req authkit.UpdateProvisioningRuleRequest,
) (authkit.ProvisioningRule, error) {
	if err := ctx.Err(); err != nil {
		return authkit.ProvisioningRule{}, err
	}

	rule := provisioningRuleFromUpdate(req)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return authkit.ProvisioningRule{}, fmt.Errorf("postgres: begin update provisioning rule: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	exists, err := provisioningRuleExists(ctx, tx, rule.ID)
	if err != nil {
		return authkit.ProvisioningRule{}, err
	}
	if !exists {
		return authkit.ProvisioningRule{}, authkit.ErrProvisioningRuleNotFound
	}
	if validationErr := validateProvisioningRule(ctx, tx, rule); validationErr != nil {
		return authkit.ProvisioningRule{}, validationErr
	}

	tag, err := tx.Exec(
		ctx,
		`update authkit_provisioning_rules
		set display_name = $2,
			provider = $3,
			condition = $4,
			enabled = $5,
			updated_at = now()
		where id = $1`,
		rule.ID,
		rule.DisplayName,
		rule.Provider,
		rule.Condition,
		rule.Enabled,
	)
	if err != nil {
		return authkit.ProvisioningRule{}, fmt.Errorf("postgres: update provisioning rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return authkit.ProvisioningRule{}, authkit.ErrProvisioningRuleNotFound
	}
	if _, err := tx.Exec(ctx, `delete from authkit_provisioning_rule_roles where rule_id = $1`, rule.ID); err != nil {
		return authkit.ProvisioningRule{}, fmt.Errorf("postgres: clear provisioning rule roles: %w", err)
	}
	if err := insertProvisioningRuleRoles(ctx, tx, rule.ID, rule.AssignRoleIDs); err != nil {
		return authkit.ProvisioningRule{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return authkit.ProvisioningRule{}, fmt.Errorf("postgres: commit update provisioning rule: %w", err)
	}

	return cloneProvisioningRule(rule), nil
}

// DeleteProvisioningRule deletes a provisioning rule from PostgreSQL.
func (s *Store) DeleteProvisioningRule(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if id == "" {
		return errors.New("postgres: provisioning rule ID is required")
	}

	tag, err := s.pool.Exec(ctx, `delete from authkit_provisioning_rules where id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete provisioning rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return authkit.ErrProvisioningRuleNotFound
	}

	return nil
}

// FindProvisioningRule returns a provisioning rule by ID.
func (s *Store) FindProvisioningRule(ctx context.Context, id string) (authkit.ProvisioningRule, error) {
	if err := ctx.Err(); err != nil {
		return authkit.ProvisioningRule{}, err
	}
	if id == "" {
		return authkit.ProvisioningRule{}, errors.New("postgres: provisioning rule ID is required")
	}

	rule, err := findProvisioningRule(ctx, s.pool, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return authkit.ProvisioningRule{}, authkit.ErrProvisioningRuleNotFound
	}
	if err != nil {
		return authkit.ProvisioningRule{}, err
	}

	return rule, nil
}

// ListProvisioningRules returns all provisioning rules.
func (s *Store) ListProvisioningRules(ctx context.Context) ([]authkit.ProvisioningRule, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	rows, err := s.pool.Query(
		ctx,
		`select r.id, r.display_name, r.provider, r.condition, r.enabled,
			coalesce(array_agg(rr.role_id order by rr.role_id)
				filter (where rr.role_id is not null), '{}'::text[]) as role_ids
		from authkit_provisioning_rules as r
		left join authkit_provisioning_rule_roles as rr on rr.rule_id = r.id
		group by r.id
		order by r.id`,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres: list provisioning rules: %w", err)
	}
	defer rows.Close()

	var rules []authkit.ProvisioningRule
	for rows.Next() {
		rule, scanErr := scanProvisioningRule(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: read provisioning rules: %w", err)
	}

	return rules, nil
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
	if err := assignInitialRoles(ctx, tx, principal.ID, req.InitialRoleIDs); err != nil {
		return authkit.ProvisionIdentityResult{}, err
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
	forwardedClaims, err := encodeClaimPaths(trusted.ForwardedClaims)
	if err != nil {
		return oidc.Provider{}, err
	}
	if _, err := s.pool.Exec(
		ctx,
		`insert into authkit_oidc_providers
			(issuer, jwks_url, audiences, supported_signing_algorithms, forwarded_claims)
		values ($1, $2, $3, $4, $5::jsonb)
		on conflict (issuer) do update set
			jwks_url = excluded.jwks_url,
			audiences = excluded.audiences,
			supported_signing_algorithms = excluded.supported_signing_algorithms,
			forwarded_claims = excluded.forwarded_claims,
			updated_at = now()`,
		trusted.Issuer,
		trusted.JWKSURL,
		trusted.Audiences,
		signingAlgorithms,
		forwardedClaims,
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
	var forwardedClaims string
	err := s.pool.QueryRow(
		ctx,
		`select issuer, audiences, jwks_url, supported_signing_algorithms,
			coalesce(forwarded_claims::text, '[]')
		from authkit_oidc_providers
		where issuer = $1`,
		issuer,
	).Scan(
		&provider.Issuer,
		&provider.Audiences,
		&provider.JWKSURL,
		&provider.SupportedSigningAlgorithms,
		&forwardedClaims,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return oidc.Provider{}, oidc.ErrProviderNotFound
	}
	if err != nil {
		return oidc.Provider{}, fmt.Errorf("postgres: find OIDC provider: %w", err)
	}
	provider.ForwardedClaims, err = decodeClaimPaths(forwardedClaims)
	if err != nil {
		return oidc.Provider{}, err
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

func (s *Store) principalExists(ctx context.Context, principalID string) (bool, error) {
	var exists bool
	if err := s.pool.QueryRow(
		ctx,
		`select exists(select 1 from authkit_principals where id = $1)`,
		principalID,
	).Scan(&exists); err != nil {
		return false, fmt.Errorf("postgres: find principal: %w", err)
	}

	return exists, nil
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

func validateProvisioningRule(ctx context.Context, query queryExecutor, rule authkit.ProvisioningRule) error {
	if rule.ID == "" {
		return errors.New("postgres: provisioning rule ID is required")
	}
	if rule.Provider == "" {
		return errors.New("postgres: provisioning rule provider is required")
	}
	if err := provisioning.ValidateCondition(rule.Condition); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	if err := validateRequiredStrings("provisioning rule role ID", rule.AssignRoleIDs); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}

	_, err := findTrustedProvider(ctx, query, rule.Provider)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: provider %q is not trusted", rule.Provider)
	}
	if err != nil {
		return err
	}

	var roleCount int
	if err := query.QueryRow(
		ctx,
		`select count(*) from authkit_roles where id = any($1)`,
		rule.AssignRoleIDs,
	).Scan(&roleCount); err != nil {
		return fmt.Errorf("postgres: validate provisioning rule roles: %w", err)
	}
	if roleCount != len(rule.AssignRoleIDs) {
		return errors.New("postgres: provisioning rule references missing role")
	}

	return nil
}

func provisioningRuleExists(ctx context.Context, query rowQuerier, id string) (bool, error) {
	var exists bool
	if err := query.QueryRow(
		ctx,
		`select exists(select 1 from authkit_provisioning_rules where id = $1)`,
		id,
	).Scan(&exists); err != nil {
		return false, fmt.Errorf("postgres: find provisioning rule: %w", err)
	}

	return exists, nil
}

func insertProvisioningRule(ctx context.Context, exec sqlExecutor, rule authkit.ProvisioningRule) error {
	if _, err := exec.Exec(
		ctx,
		`insert into authkit_provisioning_rules
			(id, display_name, provider, condition, enabled)
		values ($1, $2, $3, $4, $5)`,
		rule.ID,
		rule.DisplayName,
		rule.Provider,
		rule.Condition,
		rule.Enabled,
	); err != nil {
		if isPostgresCode(err, uniqueViolation) {
			return fmt.Errorf("postgres: provisioning rule %q already exists", rule.ID)
		}

		return fmt.Errorf("postgres: create provisioning rule: %w", err)
	}

	return nil
}

func insertProvisioningRuleRoles(
	ctx context.Context,
	exec sqlExecutor,
	ruleID string,
	roleIDs []string,
) error {
	if len(roleIDs) == 0 {
		return nil
	}
	if _, err := exec.Exec(
		ctx,
		`insert into authkit_provisioning_rule_roles (rule_id, role_id)
		select $1, unnest($2::text[])
		on conflict (rule_id, role_id) do nothing`,
		ruleID,
		roleIDs,
	); err != nil {
		return fmt.Errorf("postgres: assign provisioning rule roles: %w", err)
	}

	return nil
}

func findProvisioningRule(
	ctx context.Context,
	query rowQuerier,
	id string,
) (authkit.ProvisioningRule, error) {
	rule, err := scanProvisioningRule(query.QueryRow(
		ctx,
		`select r.id, r.display_name, r.provider, r.condition, r.enabled,
			coalesce(array_agg(rr.role_id order by rr.role_id)
				filter (where rr.role_id is not null), '{}'::text[]) as role_ids
		from authkit_provisioning_rules as r
		left join authkit_provisioning_rule_roles as rr on rr.rule_id = r.id
		where r.id = $1
		group by r.id`,
		id,
	))
	if err != nil {
		return authkit.ProvisioningRule{}, err
	}

	return rule, nil
}

func scanProvisioningRule(row scanner) (authkit.ProvisioningRule, error) {
	var rule authkit.ProvisioningRule
	if err := row.Scan(
		&rule.ID,
		&rule.DisplayName,
		&rule.Provider,
		&rule.Condition,
		&rule.Enabled,
		&rule.AssignRoleIDs,
	); err != nil {
		return authkit.ProvisioningRule{}, err
	}

	return cloneProvisioningRule(rule), nil
}

func assignInitialRoles(ctx context.Context, exec sqlExecutor, principalID string, roleIDs []string) error {
	roleIDs = uniqueStrings(roleIDs)
	if err := validateNonEmptyStrings("initial role ID", roleIDs); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	if len(roleIDs) == 0 {
		return nil
	}

	if _, err := exec.Exec(
		ctx,
		`insert into authkit_principal_roles (principal_id, role_id)
		select $1, unnest($2::text[])
		on conflict (principal_id, role_id) do nothing`,
		principalID,
		roleIDs,
	); err != nil {
		if isPostgresCode(err, foreignKeyViolation) {
			return errors.New("postgres: initial role does not exist")
		}

		return fmt.Errorf("postgres: assign initial roles: %w", err)
	}

	return nil
}

func findTrustedProvider(ctx context.Context, query rowQuerier, issuer string) (oidc.Provider, error) {
	var provider oidc.Provider
	var forwardedClaims string
	err := query.QueryRow(
		ctx,
		`select issuer, audiences, jwks_url, supported_signing_algorithms,
			coalesce(forwarded_claims::text, '[]')
		from authkit_oidc_providers
		where issuer = $1`,
		issuer,
	).Scan(
		&provider.Issuer,
		&provider.Audiences,
		&provider.JWKSURL,
		&provider.SupportedSigningAlgorithms,
		&forwardedClaims,
	)
	if err != nil {
		return oidc.Provider{}, err
	}

	provider.ForwardedClaims, err = decodeClaimPaths(forwardedClaims)
	if err != nil {
		return oidc.Provider{}, err
	}

	return cloneProvider(provider), nil
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

func encodeClaimPaths(paths []authkit.ClaimPath) (string, error) {
	if len(paths) == 0 {
		return "[]", nil
	}

	encoded, err := json.Marshal(paths)
	if err != nil {
		return "", fmt.Errorf("postgres: encode claim paths: %w", err)
	}

	return string(encoded), nil
}

func decodeClaimPaths(encoded string) ([]authkit.ClaimPath, error) {
	if encoded == "" || encoded == "null" {
		return nil, nil
	}

	var paths []authkit.ClaimPath
	if err := json.Unmarshal([]byte(encoded), &paths); err != nil {
		return nil, fmt.Errorf("postgres: decode claim paths: %w", err)
	}
	if len(paths) == 0 {
		return nil, nil
	}

	return cloneClaimPaths(paths), nil
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
	provider.ForwardedClaims = cloneClaimPaths(provider.ForwardedClaims)

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

func cloneClaimPaths(paths []authkit.ClaimPath) []authkit.ClaimPath {
	if len(paths) == 0 {
		return nil
	}

	cloned := make([]authkit.ClaimPath, len(paths))
	for i, path := range paths {
		cloned[i] = cloneClaimPath(path)
	}

	return cloned
}

func cloneClaimPath(path authkit.ClaimPath) authkit.ClaimPath {
	if len(path) == 0 {
		return nil
	}

	cloned := make(authkit.ClaimPath, len(path))
	copy(cloned, path)

	return cloned
}

func provisioningRuleFromCreate(req authkit.CreateProvisioningRuleRequest) authkit.ProvisioningRule {
	return normalizeProvisioningRule(authkit.ProvisioningRule{
		ID:            req.ID,
		DisplayName:   req.DisplayName,
		Provider:      req.Provider,
		Condition:     provisioning.NormalizeCondition(req.Condition),
		AssignRoleIDs: cloneStrings(req.AssignRoleIDs),
		Enabled:       req.Enabled,
	})
}

func provisioningRuleFromUpdate(req authkit.UpdateProvisioningRuleRequest) authkit.ProvisioningRule {
	return normalizeProvisioningRule(authkit.ProvisioningRule{
		ID:            req.ID,
		DisplayName:   req.DisplayName,
		Provider:      req.Provider,
		Condition:     provisioning.NormalizeCondition(req.Condition),
		AssignRoleIDs: cloneStrings(req.AssignRoleIDs),
		Enabled:       req.Enabled,
	})
}

func normalizeProvisioningRule(rule authkit.ProvisioningRule) authkit.ProvisioningRule {
	rule.AssignRoleIDs = uniqueStrings(rule.AssignRoleIDs)

	return rule
}

func cloneProvisioningRule(rule authkit.ProvisioningRule) authkit.ProvisioningRule {
	rule.AssignRoleIDs = cloneStrings(rule.AssignRoleIDs)

	return rule
}

func validateNonEmptyStrings(name string, values []string) error {
	for i, value := range values {
		if value == "" {
			return fmt.Errorf("%s %d is required", name, i)
		}
	}

	return nil
}

func validateRequiredStrings(name string, values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("%s is required", name)
	}

	return validateNonEmptyStrings(name, values)
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	unique := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}

		seen[value] = struct{}{}
		unique = append(unique, value)
	}

	return unique
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
