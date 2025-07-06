package gocbc

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
)

const (
	cookieName    = "session_token"
	protectedPath = "/protected"
	loginPath     = "/login"
)

type user struct {
	jwt.RegisteredClaims
	ConfirmationClaim
	Username    string   `json:"username"`
	Permissions []string `json:"permissions"`
}

var (
	johndoeClaims = &user{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  "trustedIdP",
			Subject: "uuid",
		},
		Username:    "johndoe",
		Permissions: []string{"read", "write"},
	}
)

func setupClient(t *testing.T) *http.Client {
	t.Helper()

	signer, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err, "Failed to generate default signer")

	clientCert, _ := localCA.Sign(&x509.Certificate{
		PublicKey: signer.Public(),
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature,
	})
	cert := tls.Certificate{
		Certificate: [][]byte{clientCert.Raw, localCA.Intermediate.Raw},
		PrivateKey:  signer,
	}

	pool := x509.NewCertPool()
	pool.AddCert(localCA.Root)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err, "Failed to create cookie jar")

	return &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				RootCAs:      pool,
			},
		},
	}
}

func setupServerTlsConfig(t *testing.T) *tls.Config {
	t.Helper()

	signer, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err, "Failed to generate default signer")

	serverCert, _ := localCA.Sign(&x509.Certificate{
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
		PublicKey:   signer.Public(),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	})
	cert := tls.Certificate{
		Certificate: [][]byte{serverCert.Raw, localCA.Intermediate.Raw},
		PrivateKey:  signer,
	}
	pool := x509.NewCertPool()
	pool.AddCert(localCA.Root)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		ClientCAs:    pool,
	}
}

func setupServer(t *testing.T, handerFn func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(handerFn))
	srv.TLS = setupServerTlsConfig(t)
	return srv
}
