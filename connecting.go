package goapiauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
)

// Connecting is a TokenVerifier that has not yet read the identity provider.
// Until Run has built its Verifier it refuses every token as
// ErrProviderUnavailable. A provider that is down when the API starts then
// holds back only the requests that need a token, and the rest of the API
// carries on.
type Connecting struct {
	config                Config
	firstRetry, lastRetry time.Duration

	verifier atomic.Pointer[Verifier]
	failure  atomic.Pointer[error]
}

// NewConnecting is a Connecting for config. Run starts it.
func NewConnecting(config Config) *Connecting {
	return &Connecting{config: config, firstRetry: time.Second, lastRetry: time.Minute}
}

// Run builds the Verifier, retrying after each failure with a wait that
// doubles from a second to a minute, until it succeeds or ctx ends. A
// discovery document naming another issuer is retried too, because a provider
// still starting can serve one, and every retry is logged.
func (c *Connecting) Run(ctx context.Context, log *slog.Logger) {
	wait := c.firstRetry
	for {
		verifier, err := NewVerifier(ctx, c.config)
		switch {
		case err == nil:
			c.verifier.Store(verifier)
			log.InfoContext(ctx, "identity provider read", "issuer", c.config.Issuer)
			return
		case ctx.Err() != nil:
			return
		}
		c.failure.Store(&err)
		switch {
		case errors.Is(err, ErrProviderUnavailable):
			log.WarnContext(ctx, "identity provider not read", "issuer", c.config.Issuer, "err", err, "retry_in", wait.String())
		default:
			log.ErrorContext(ctx, "identity provider misconfigured", "issuer", c.config.Issuer, "err", err, "retry_in", wait.String())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(2*wait, c.lastRetry)
	}
}

// Ready is nil once Run has built the Verifier, and before then the last
// reason it could not.
func (c *Connecting) Ready() error {
	if c.verifier.Load() != nil {
		return nil
	}
	if failure := c.failure.Load(); failure != nil {
		return *failure
	}
	return fmt.Errorf("%w: its discovery document and keys are not read yet", ErrProviderUnavailable)
}

// Verify verifies raw with the Verifier Run built, and refuses it as
// ErrProviderUnavailable before there is one.
func (c *Connecting) Verify(ctx context.Context, raw string) (Identity, error) {
	verifier := c.verifier.Load()
	if verifier == nil {
		return Identity{}, fmt.Errorf("%w: its discovery document and keys are not read yet", ErrProviderUnavailable)
	}
	return verifier.Verify(ctx, raw)
}
