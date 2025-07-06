package gocbc

import (
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
)

var localCA *minica.CA

func init() {
	var err error
	localCA, err = minica.New()
	if err != nil {
		panic("Failed to create local CA: " + err.Error())
	}
}

func Test_getConfirmationClaim(t *testing.T) {
	tests := []struct {
		name     string
		filepath string
		want     *ConfirmationClaim
	}{
		{
			// i.e. https://datatracker.ietf.org/doc/html/rfc8705#name-example-cnf-claim-certifica
			name:     "cert from RFC 8705 (Appendix A.)",
			filepath: "./testdata/cert_from_rfc8705.pem",
			want:     &ConfirmationClaim{confirmationClaim{Thumbprint: "A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0"}},
		},
		{
			name:     "cert tested with keycloak v26.2.5",
			filepath: "./testdata/cert_tested_with_keycloak.pem",
			want:     &ConfirmationClaim{confirmationClaim{Thumbprint: "ppc1R15JEQ5bQ-FJrR-egaRgdiQCeMHAsOLTnx0uLP4"}},
		},
		{
			name:     "no cert",
			filepath: "",
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				cert *x509.Certificate
				err  error
			)
			if tt.filepath != "" {
				cert, err = pemutil.ReadCertificate(tt.filepath)
			}
			require.NoError(t, err, fmt.Sprintf("failed to read %s", tt.filepath))
			got := getConfirmationClaim(cert)
			require.Equal(t, tt.want, got)
		})
	}
}

type CompliantCustomClaims struct {
	ConfirmationClaim
	jwt.RegisteredClaims
}

func TestCreate(t *testing.T) {
	signer, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatalf("failed to generate signer: %v", err)
	}
	cert, _ := localCA.Sign(&x509.Certificate{
		DNSNames:  []string{"leaf.test.com"},
		PublicKey: signer.Public(),
	})
	thumbprint := getConfirmationClaim(cert).Thumbprint

	type InvalidCustomClaims struct {
		jwt.RegisteredClaims
	}

	type args struct {
		cert   *x509.Certificate
		claims func() jwt.Claims
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "ok with custom claim",
			args: args{
				cert,
				func() jwt.Claims {
					return &CompliantCustomClaims{
						RegisteredClaims: jwt.RegisteredClaims{
							Issuer: "test",
						},
					}
				},
			},
			wantErr: nil,
		},
		{
			name: "ok with jwt.MapClaims",
			args: args{
				cert,
				func() jwt.Claims {
					return jwt.MapClaims{
						"iss": "test",
					}
				},
			},
			wantErr: nil,
		},
		{
			name: "ko jwt.RegisteredClaims",
			args: args{
				cert,
				func() jwt.Claims {
					return jwt.RegisteredClaims{
						Issuer: "test",
					}
				},
			},
			wantErr: errors.ErrUnsupported,
		},
		{
			name: "ko struct doesn't implement CertificateBoundClaimsUpdater",
			args: args{
				cert,
				func() jwt.Claims {
					return &InvalidCustomClaims{
						RegisteredClaims: jwt.RegisteredClaims{
							Issuer: "test",
						},
					}
				},
			},
			wantErr: ErrMustImplementUpdaterInterface,
		},
		{
			name: "ko certificate is nil",
			args: args{
				nil,
				func() jwt.Claims {
					return jwt.RegisteredClaims{
						Issuer: "test",
					}
				},
			},
			wantErr: ErrCertCannotBeNil,
		},
		{
			name: "ko claims is nil",
			args: args{
				cert,
				func() jwt.Claims {
					return nil
				},
			},
			wantErr: ErrClaimsCannotBeNil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Create(tt.args.cert, tt.args.claims())
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				cfn, err := got.GetConfirmation()
				require.NoError(t, err, "GetConfirmation() failed")
				require.Equal(t, thumbprint, cfn.Thumbprint)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	signer, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatalf("failed to generate signer: %v", err)
	}
	unstredSigner, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatalf("failed to generate untrusted signer: %v", err)
	}
	trustedCert, _ := localCA.Sign(&x509.Certificate{
		DNSNames:  []string{"leaf.test.com"},
		PublicKey: signer.Public(),
	})
	untrustedCert, _ := localCA.Sign(&x509.Certificate{
		DNSNames:  []string{"leaf.test.com"},
		PublicKey: unstredSigner.Public(),
	})
	jwtSigner := []byte("secret")

	initHook := func(t *testing.T) CertificateBoundClaims {
		c, err := Create(trustedCert, &CompliantCustomClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer: "test",
			},
		})
		require.NoError(t, err, "Create() failed")
		return c
	}
	tests := []struct {
		name       string
		verifyCert *x509.Certificate
		claims     func(t *testing.T) CertificateBoundClaims
		want       error
	}{
		{
			name: "ok from struct",
			claims: func(t *testing.T) CertificateBoundClaims {
				return initHook(t)
			},
			verifyCert: trustedCert,
			want:       nil,
		},
		{
			name: "ok from raw JWT",
			claims: func(t *testing.T) CertificateBoundClaims {
				claims := initHook(t)

				jwtStr := createJWT(t, claims, jwtSigner)

				token, err := jwt.ParseWithClaims(
					jwtStr,
					&CompliantCustomClaims{},
					func(token *jwt.Token) (any, error) {
						return jwtSigner, nil
					},
				)
				require.NoError(t, err, "ParseWithClaims() failed")
				return token.Claims.(*CompliantCustomClaims)
			},
			verifyCert: trustedCert,
			want:       nil,
		},
		{
			name: "ko thumbprint mismatch",
			claims: func(t *testing.T) CertificateBoundClaims {
				return initHook(t)
			},
			verifyCert: untrustedCert,
			want:       ErrThumprintMismatch,
		},
		{
			name: "ko cert is nil",
			claims: func(t *testing.T) CertificateBoundClaims {
				return initHook(t)
			},
			verifyCert: nil,
			want:       ErrCertCannotBeNil,
		},
		{
			name: "ko CertificateBoundClaims is nil",
			claims: func(t *testing.T) CertificateBoundClaims {
				return nil
			},
			verifyCert: trustedCert,
			want:       ErrClaimsCannotBeNil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Verify(tt.verifyCert, tt.claims(t))
			require.Equal(t, tt.want, got)
		})
	}
}

func createJWT(t *testing.T, claims jwt.Claims, shareKey []byte) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(shareKey)
	require.NoError(t, err, "failed to sign the JWT")
	return ss
}
