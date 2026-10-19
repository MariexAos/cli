// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"fmt"

	"github.com/larksuite/cli/errs"
	"github.com/larksuite/cli/internal/output"
	"github.com/larksuite/cli/internal/recovery"
)

const (
	needUserAuthorizationMarker = "need_user_authorization"
)

// TokenRetryCodes contains error codes that allow retry after token refresh.
var TokenRetryCodes = map[int]bool{
	output.LarkErrTokenInvalid: true,
	output.LarkErrTokenExpired: true,
}

// NeedAuthorizationError is the sentinel preserved in the Cause chain of the
// typed missing-UAT error so existing errors.As(&NeedAuthorizationError{})
// consumers keep matching after the construction site moved to the typed
// taxonomy. It is never surfaced on the wire on its own.
type NeedAuthorizationError struct {
	UserOpenId string
}

// Error returns the error message for NeedAuthorizationError.
func (e *NeedAuthorizationError) Error() string {
	return fmt.Sprintf("%s (user: %s)", needUserAuthorizationMarker, e.UserOpenId)
}

// NewNeedUserAuthorizationError builds the typed *errs.AuthenticationError
// returned when no valid UAT exists for userOpenID. The Message keeps the
// need_user_authorization marker, the Hint converges on the same auth-login
// recovery vocabulary as the token-missing surface in internal/client, and the
// legacy *NeedAuthorizationError sentinel is preserved in the Cause chain for
// errors.As / errors.Is traversal.
func NewNeedUserAuthorizationError(userOpenID string) error {
	return newNeedUserAuthorizationError(userOpenID, nil, recovery.UserAuthorization())
}

// newNeedUserAuthorizationError preserves the missing-UAT sentinel alongside
// an optional lower-layer cause and attaches build-local recovery metadata.
func newNeedUserAuthorizationError(userOpenID string, cause error, hint recovery.Hint) error {
	needAuthCause := error(&NeedAuthorizationError{UserOpenId: userOpenID})
	if cause != nil {
		needAuthCause = errors.Join(needAuthCause, cause)
	}

	e := errs.NewAuthenticationError(errs.SubtypeTokenMissing,
		"%s (user: %s)", needUserAuthorizationMarker, userOpenID).
		WithUserOpenID(userOpenID).
		WithCause(needAuthCause)
	return recovery.Attach(e, hint)
}

// newConsumedRefreshTokenAuthorizationError reports the missing UAT left
// behind after this process cleared a token whose refresh_token the server
// reported as already used or revoked. It keeps the need_user_authorization
// type, subtype, and message marker, and adds the reason and the
// credential-copy guidance so the re-authorization prompt is explainable.
func newConsumedRefreshTokenAuthorizationError(userOpenID string, refreshErr error) error {
	err := newNeedUserAuthorizationError(userOpenID, refreshErr, consumedRefreshTokenHint())
	if problem, ok := errs.ProblemOf(err); ok {
		problem.Message += ": " + consumedRefreshTokenReason(refreshErr) + ", so the local token was cleared"
	}
	return err
}

// isConsumedRefreshTokenError reports whether the token endpoint rejected a
// refresh_token as already used or revoked. Refresh tokens are single-use, so
// both normally mean another holder of the same credentials refreshed first.
func isConsumedRefreshTokenError(err error) bool {
	problem, ok := errs.ProblemOf(err)
	return ok && (problem.Subtype == errs.SubtypeRefreshTokenReused ||
		problem.Subtype == errs.SubtypeRefreshTokenRevoked)
}

func consumedRefreshTokenReason(err error) string {
	if problem, ok := errs.ProblemOf(err); ok && problem.Subtype == errs.SubtypeRefreshTokenRevoked {
		return "the stored refresh_token was revoked; refresh tokens are single-use, so another lark-cli process or environment most likely used it first"
	}
	return "the stored refresh_token was already used by another lark-cli process or environment"
}

// consumedRefreshTokenHint explains how one refresh_token reaches two holders
// before pointing at the canonical re-authorization recovery.
func consumedRefreshTokenHint() recovery.Hint {
	return recovery.JoinHints("\n",
		recovery.Join("", recovery.Text("a refresh_token can be used only once; "+
			"check whether the lark-cli config directory or token storage directory (including LARKSUITE_CLI_DATA_DIR) "+
			"was copied or synced to another machine, container, or sandbox, or restored from a snapshot or image, "+
			"and stop the other copy from refreshing before re-authorizing")),
		recovery.UserAuthorization(),
	)
}

// IsNeedUserAuthorizationError reports whether err represents a missing-UAT
// failure. It matches the legacy *NeedAuthorizationError sentinel, which is
// preserved in the Cause chain of the typed missing-UAT error, so errors.As
// traverses into the typed *errs.AuthenticationError as well.
func IsNeedUserAuthorizationError(err error) bool {
	if err == nil {
		return false
	}

	var needAuthErr *NeedAuthorizationError
	return errors.As(err, &needAuthErr)
}

// SecurityPolicyError is preserved as a Go type alias so existing
// errors.As(&SecurityPolicyError{}) consumers (cmd/root.go etc.) keep working.
// The concrete struct lives in errs/types.go.
type SecurityPolicyError = errs.SecurityPolicyError
