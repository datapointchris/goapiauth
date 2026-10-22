package goapiauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/sync/singleflight"

	"github.com/datapointchris/goapiauth/clientid"
)

// ErrUnauthorized is returned for every rejected token. The reason is wrapped
// for the API's log rather than sent to the caller, so a probe cannot learn
// which check it failed.
var ErrUnauthorized = errors.New("unauthorized")

// ErrProviderUnavailable is the identity provider not answering, or answering
// with no usable keys, as distinct from a token that is bad. A caller holding
// a good token cannot fix it by logging in again.
var ErrProviderUnavailable = errors.New("identity provider unavailable")

// providerTimeout bounds each request to the provider. Without it a provider
// that accepts the connection and never replies holds every caller waiting on
// it.
const providerTimeout = 10 * time.Second

// keySetLifespan is how old held keys grow before a token they verify asks for
// them to be read again, which bounds how long a key the provider stopped
// publishing still verifies. It is never a cutoff: keys that cannot be read
// again go on verifying.
const keySetLifespan = 5 * time.Minute

// keyRereadGap is the least time between two reads of the provider's keys.
// Anyone who reaches the API can send a token no held key verifies, so without
// it a stream of forged tokens is a stream of reads.
const keyRereadGap = 30 * time.Second

// userAgent names this library to the provider. A proxy in front of a provider
// can refuse a client that names none.
const userAgent = "goapiauth"

// signingAlgorithm is the one algorithm the provider signs access tokens with.
// A token naming another is refused before any key is tried.
const signingAlgorithm = jose.RS256

// Config names the provider an API trusts and the clients whose tokens it
// accepts.
type Config struct {
	// Issuer is the provider's issuer URL, as its discovery document names it.
	Issuer string

	// PersonPrefix starts the client id of every person's CLI the API accepts:
	// clientid.PersonPrefix("acme") for acme-cli-<host>. The audience claim is
	// not checked, so the prefix is what keeps a token issued to another
	// product's CLI out.
	PersonPrefix string

	// ServicePrefix starts the client id of every client-credentials client the
	// API accepts: clientid.ServicePrefix("acme") for acme-svc-<name>. Empty
	// refuses every service token.
	ServicePrefix string
}

// check refuses a prefix clientid could not have built. A bare product name
// would admit every client id it starts: acme admits acmecorp-cli-desk.
func (c Config) check() error {
	if c.Issuer == "" {
		return errors.New("goapiauth: Config needs an Issuer")
	}
	if !builtBy(c.PersonPrefix, clientid.PersonPrefix) {
		return fmt.Errorf("goapiauth: PersonPrefix %q is not clientid.PersonPrefix(product) for any product", c.PersonPrefix)
	}
	if c.ServicePrefix != "" && !builtBy(c.ServicePrefix, clientid.ServicePrefix) {
		return fmt.Errorf("goapiauth: ServicePrefix %q is not clientid.ServicePrefix(product) for any product", c.ServicePrefix)
	}
	if c.ServicePrefix != "" && (strings.HasPrefix(c.PersonPrefix, c.ServicePrefix) || strings.HasPrefix(c.ServicePrefix, c.PersonPrefix)) {
		return fmt.Errorf("goapiauth: client prefixes %q and %q overlap", c.PersonPrefix, c.ServicePrefix)
	}
	return nil
}

// builtBy reports whether prefix is build(product) for a product that is not
// empty.
func builtBy(prefix string, build func(product string) string) bool {
	product, ok := strings.CutSuffix(prefix, build(""))
	return ok && product != ""
}

// Identity is what a verified token or a browser session establishes about the
// caller.
type Identity struct {
	// Subject is the person. A service's token carries none.
	Subject string

	// ClientID is the client the token was issued to. A session carries none.
	ClientID string

	// Service is set for a service client's token, which carries Scopes and no
	// Subject. LimitServices keeps it to the routes Scopes list.
	Service bool
	Scopes  []string

	// Groups is the person's groups: a token's groups claim, or the groups a
	// gobrowserlogin session holds. RequireGroup reads it.
	Groups []string
}

// Verifier checks token signatures against the issuer's published keys and
// the claims against Config.
type Verifier struct {
	config Config
	keys   *keySet
	now    func() time.Time
}

// namedAgent sets the User-Agent on every request to the provider.
type namedAgent struct{ base http.RoundTripper }

func (n namedAgent) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", userAgent)
	return n.base.RoundTrip(req)
}

func identifiedClient() *http.Client {
	return &http.Client{Timeout: providerTimeout, Transport: namedAgent{base: http.DefaultTransport}}
}

type discoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// NewVerifier reads the issuer's discovery document and then the keys it
// publishes, so a Verifier that exists can verify a token. A provider that
// cannot be read is ErrProviderUnavailable. An API that should start while
// the provider is down uses NewConnecting.
//
// The prefixes may not overlap. Otherwise one client would match both, and
// which kind it was would depend on the order they are checked in.
func NewVerifier(ctx context.Context, config Config) (*Verifier, error) {
	if err := config.check(); err != nil {
		return nil, err
	}
	doc, err := readDiscovery(ctx, config.Issuer)
	if err != nil {
		return nil, err
	}
	if doc.Issuer != config.Issuer {
		return nil, fmt.Errorf("goapiauth: issuer %q advertises itself as %q", config.Issuer, doc.Issuer)
	}
	if doc.JWKSURI == "" {
		return nil, fmt.Errorf("goapiauth: issuer %q advertises no jwks_uri", config.Issuer)
	}
	keys := &keySet{uri: doc.JWKSURI, client: identifiedClient()}
	if _, err := keys.fetch(ctx, time.Now()); err != nil {
		return nil, err
	}
	return &Verifier{config: config, keys: keys, now: time.Now}, nil
}

func readDiscovery(ctx context.Context, issuer string) (discoveryDocument, error) {
	ctx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()

	url := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return discoveryDocument{}, fmt.Errorf("goapiauth: %w", err)
	}
	resp, err := identifiedClient().Do(req)
	if err != nil {
		return discoveryDocument{}, fmt.Errorf("%w: reach %s: %w", ErrProviderUnavailable, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return discoveryDocument{}, fmt.Errorf("%w: %s answered %s", ErrProviderUnavailable, url, resp.Status)
	}
	var doc discoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return discoveryDocument{}, fmt.Errorf("%w: decode %s: %w", ErrProviderUnavailable, url, err)
	}
	return doc, nil
}

type accessTokenClaims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	ClientID string   `json:"client_id"`
	Expiry   int64    `json:"exp"`
	Groups   []string `json:"groups"`

	// Scopes is decoded only for a service client, so a person's token whose
	// scp has some other shape is not refused for it.
	Scopes json.RawMessage `json:"scp"`
}

// Verify checks the header type, the signature, and then every claim the API
// relies on. A bad token is ErrUnauthorized and a provider whose keys cannot
// be read is ErrProviderUnavailable, each with the reason wrapped for logging.
// ctx ending while the keys are read returns ctx's own error.
//
// A person's token must carry a subject. A service's must carry scopes. A
// missing subject cannot decide which a token is: some providers leave sub off
// a client-credentials token, but RFC 9068 requires one, and a release that
// adds it would make a service look like a person. So the client id decides.
func (v *Verifier) Verify(ctx context.Context, raw string) (Identity, error) {
	signed, err := parseAccessToken(raw)
	if err != nil {
		return Identity{}, err
	}
	payload, err := v.keys.verify(ctx, signed, v.now())
	if err != nil {
		return Identity{}, err
	}

	var claims accessTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Identity{}, fmt.Errorf("%w: claims are not JSON: %w", ErrUnauthorized, err)
	}
	switch {
	case claims.Issuer != v.config.Issuer:
		return Identity{}, fmt.Errorf("%w: issuer %q", ErrUnauthorized, claims.Issuer)
	case claims.Expiry == 0 || v.now().After(time.Unix(claims.Expiry, 0)):
		return Identity{}, fmt.Errorf("%w: expired", ErrUnauthorized)
	case strings.HasPrefix(claims.ClientID, v.config.PersonPrefix):
		if claims.Subject == "" {
			return Identity{}, fmt.Errorf("%w: no subject", ErrUnauthorized)
		}
		return Identity{Subject: claims.Subject, ClientID: claims.ClientID, Groups: claims.Groups}, nil
	case v.config.ServicePrefix != "" && strings.HasPrefix(claims.ClientID, v.config.ServicePrefix):
		scopes, err := serviceScopes(claims.Scopes)
		if err != nil {
			return Identity{}, fmt.Errorf("%w: service client %q: %w", ErrUnauthorized, claims.ClientID, err)
		}
		return Identity{ClientID: claims.ClientID, Service: true, Scopes: scopes}, nil
	default:
		return Identity{}, fmt.Errorf("%w: client %q is not one this API accepts", ErrUnauthorized, claims.ClientID)
	}
}

// serviceScopes is scp as a service client's token must carry it: a list of at
// least one non-empty string. An empty or missing scp is refused.
func serviceScopes(raw json.RawMessage) ([]string, error) {
	var scopes []string
	if err := json.Unmarshal(raw, &scopes); err != nil {
		return nil, fmt.Errorf("scp is not a list of strings: %s", raw)
	}
	if len(scopes) == 0 || slices.Contains(scopes, "") {
		return nil, fmt.Errorf("scp names no scope: %s", raw)
	}
	return scopes, nil
}

// parseAccessToken reads raw as a compact JWS signed with signingAlgorithm and
// typed as an RFC 9068 access token. An id_token from the same issuer carries
// a valid signature and issuer, and it is handed to the client, so without the
// type check it would authenticate.
func parseAccessToken(raw string) (*jose.JSONWebSignature, error) {
	if strings.Count(raw, ".") != 2 {
		return nil, fmt.Errorf("%w: not a compact JWT", ErrUnauthorized)
	}
	signed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{signingAlgorithm})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	typ, _ := signed.Signatures[0].Protected.ExtraHeaders[jose.HeaderType].(string)
	if !strings.EqualFold(typ, "at+jwt") {
		return nil, fmt.Errorf("%w: token type %q is not at+jwt", ErrUnauthorized, typ)
	}
	return signed, nil
}

// keySet holds the signing keys the provider publishes at uri. A token no held
// key verifies makes it read them again, which covers a key the provider has
// rotated in, and so do held keys older than keySetLifespan, which covers one
// it has rotated out. Reads are keyRereadGap apart at least, and callers
// waiting at the same moment share one.
type keySet struct {
	uri     string
	client  *http.Client
	fetches singleflight.Group

	mu    sync.Mutex
	keys  []jose.JSONWebKey
	read  time.Time
	tried time.Time

	// failed is the last read's error, nil once a read succeeds. Inside the
	// gap after a failed read, a token no held key verifies may be signed by a
	// key the provider rotated in, so it is refused as the outage it met.
	failed error
}

// verify is the payload of signed as the provider's keys verify it. A token
// the held keys verify is answered from them at once. Held keys past
// keySetLifespan also start a read the token does not wait on, because a
// provider that cannot be read has not rotated them out. A token they do not
// verify waits on a read.
func (s *keySet) verify(ctx context.Context, signed *jose.JSONWebSignature, now time.Time) ([]byte, error) {
	s.mu.Lock()
	held, read, tried, failed := s.keys, s.read, s.tried, s.failed
	s.mu.Unlock()

	rereadDue := now.Sub(tried) >= keyRereadGap
	if payload, ok := verifyWith(held, signed); ok {
		if rereadDue && now.Sub(read) >= keySetLifespan {
			s.refresh(now)
		}
		return payload, nil
	}
	switch {
	case !rereadDue && failed != nil:
		return nil, failed
	case !rereadDue:
		return nil, fmt.Errorf("%w: no key the provider publishes verifies the signature", ErrUnauthorized)
	}

	keys, err := s.reread(ctx, now)
	if err != nil {
		return nil, err
	}
	if payload, ok := verifyWith(keys, signed); ok {
		return payload, nil
	}
	return nil, fmt.Errorf("%w: no key the provider publishes verifies the signature", ErrUnauthorized)
}

// refresh starts a read of the keys, or joins the one running, and returns
// where its result arrives. The read runs on a deadline of its own rather than
// a caller's, since every caller waiting shares it and any of them can stop
// waiting.
func (s *keySet) refresh(now time.Time) <-chan singleflight.Result {
	return s.fetches.DoChan("keys", func() (any, error) {
		s.mu.Lock()
		s.tried = now
		s.mu.Unlock()
		keys, err := s.fetch(context.Background(), now)
		s.mu.Lock()
		s.failed = err
		s.mu.Unlock()
		return keys, err
	})
}

// reread waits on refresh. ctx ending returns ctx's own error and leaves the
// read running for the rest.
func (s *keySet) reread(ctx context.Context, now time.Time) ([]jose.JSONWebKey, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("goapiauth: read the provider's keys: %w", ctx.Err())
	case result := <-s.refresh(now):
		if result.Err != nil {
			return nil, result.Err
		}
		return result.Val.([]jose.JSONWebKey), nil
	}
}

// fetch reads the keys the provider publishes and holds them, giving up at
// providerTimeout or when ctx ends. now is when the keys count as read.
func (s *keySet) fetch(ctx context.Context, now time.Time) ([]jose.JSONWebKey, error) {
	ctx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.uri, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("goapiauth: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: reach %s: %w", ErrProviderUnavailable, s.uri, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s answered %s", ErrProviderUnavailable, s.uri, resp.Status)
	}
	var published jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&published); err != nil {
		return nil, fmt.Errorf("%w: decode %s: %w", ErrProviderUnavailable, s.uri, err)
	}
	var signing []jose.JSONWebKey
	for _, key := range published.Keys {
		if key.Use == "" || key.Use == "sig" {
			signing = append(signing, key)
		}
	}
	if len(signing) == 0 {
		return nil, fmt.Errorf("%w: %s publishes no signing key", ErrProviderUnavailable, s.uri)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = signing
	s.read = now
	return signing, nil
}

// verifyWith is the payload of signed as one of keys verifies it. Every key is
// the provider's, so the key id the token names decides nothing a signature
// does not.
func verifyWith(keys []jose.JSONWebKey, signed *jose.JSONWebSignature) ([]byte, bool) {
	for i := range keys {
		if payload, err := signed.Verify(&keys[i]); err == nil {
			return payload, true
		}
	}
	return nil, false
}
