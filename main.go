package cbc

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"go.step.sm/crypto/x509util"
)

const (
	CONFIRMATION_CLAIM        = "cnf"
	CONFIRMATION_METHOD_CLAIM = "x5t#S256"
)

var (
	ErrThumprintMismatch             = errors.New("thumbprint mismatch between the given certificate and the one stored in 'cnf' claim")
	ErrMustImplementUpdaterInterface = errors.New("given type must implement 'CertificateBoundClaimsUpdater' interface")
	ErrClaimsCannotBeNil             = errors.New("claims cannot be nil")
	ErrCertCannotBeNil               = errors.New("certificate cannot be nil")
)

type ConfirmationGetter interface {
	GetConfirmation() (ConfirmationClaim, error)
}

type CertificateBoundClaims interface {
	jwt.Claims
	ConfirmationGetter
}

type CertificateBoundClaimsUpdater interface {
	CertificateBoundClaims
	SetConfirmation(ConfirmationClaim)
}

type ConfirmationClaim struct {
	confirmationClaim `json:"cnf"`
}

type confirmationClaim struct {
	Thumbprint string `json:"x5t#S256"`
}

func NewConfirmationClaim(cert *x509.Certificate) *ConfirmationClaim {
	return getConfirmationClaim(cert)
}

func (c ConfirmationClaim) GetConfirmation() (ConfirmationClaim, error) {
	return c, nil
}

func (c *ConfirmationClaim) SetConfirmation(cnf ConfirmationClaim) {
	c.Thumbprint = cnf.Thumbprint
}

func (c ConfirmationClaim) Verify(cert *x509.Certificate) error {
	if cert == nil {
		return ErrCertCannotBeNil
	}
	if c.Thumbprint != getConfirmationClaim(cert).Thumbprint {
		return ErrThumprintMismatch
	}
	return nil
}

func Create(cert *x509.Certificate, claims jwt.Claims) (CertificateBoundClaims, error) {
	if cert == nil {
		return nil, ErrCertCannotBeNil
	}
	cnf := getConfirmationClaim(cert)
	switch c := claims.(type) {
	case jwt.MapClaims:
		c[CONFIRMATION_CLAIM] = cnf.confirmationClaim
		return MapClaims{MapClaims: c}, nil
	case jwt.RegisteredClaims:
		return nil, errors.ErrUnsupported
	case nil:
		return nil, ErrClaimsCannotBeNil
	}
	certBoundUpdater, ok := claims.(CertificateBoundClaimsUpdater)
	if !ok {
		return nil, ErrMustImplementUpdaterInterface
	}
	certBoundUpdater.SetConfirmation(*cnf)
	return certBoundUpdater, nil
}

func Verify(cert *x509.Certificate, claims CertificateBoundClaims) error {
	if claims == nil {
		return ErrClaimsCannotBeNil
	}
	cnf, err := claims.(ConfirmationGetter).GetConfirmation()
	if err != nil {
		return fmt.Errorf("cannot retrieve confirmation object: %w", err)
	}
	return cnf.Verify(cert)
}

func getConfirmationClaim(cert *x509.Certificate) *ConfirmationClaim {
	if cert == nil {
		return nil
	}
	return &ConfirmationClaim{confirmationClaim{
		x509util.EncodedFingerprint(cert, x509util.Base64RawURLFingerprint),
	}}
}
