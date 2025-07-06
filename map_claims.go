package gocbc

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

var _ CertificateBoundClaims = (*MapClaims)(nil)

type MapClaims struct {
	jwt.MapClaims
	callback GetCertificateFn
}

func (m *MapClaims) RegisterCallback(callback GetCertificateFn) *MapClaims {
	m.callback = callback
	return m
}

func (m MapClaims) Validate() error {
	if m.callback != nil {
		return Verify(m.callback(), m)
	}
	return nil
}

func (m MapClaims) GetConfirmation() (ConfirmationClaim, error) {
	return m.parseConfirmationClaim()
}

func (m MapClaims) parseConfirmationClaim() (ConfirmationClaim, error) {
	var (
		ok     bool
		raw    any
		nilCnf ConfirmationClaim
	)
	raw, ok = m.MapClaims[CONFIRMATION_CLAIM]
	if !ok {
		return nilCnf, nil
	}

	switch cnf := raw.(type) {
	case map[string]any:
		thumbprint, ok := cnf[CONFIRMATION_METHOD_CLAIM]
		if !ok {
			return nilCnf, nil
		}
		return ConfirmationClaim{confirmationClaim{Thumbprint: thumbprint.(string)}}, nil
	case confirmationClaim:
		return ConfirmationClaim{cnf}, nil
	default:
		return nilCnf, newError(fmt.Sprintf("%s is invalid", CONFIRMATION_CLAIM), jwt.ErrInvalidType)
	}
}

func newError(message string, err error, more ...error) error {
	var format string
	var args []any
	if message != "" {
		format = "%w: %s"
		args = []any{err, message}
	} else {
		format = "%w"
		args = []any{err}
	}

	for _, e := range more {
		format += ": %w"
		args = append(args, e)
	}

	err = fmt.Errorf(format, args...)
	return err
}
