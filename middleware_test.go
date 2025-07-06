package gocbc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestCertificateBoundCookieMiddleware(t *testing.T) {
	jwtSigner := []byte("verysecurekey")
	getConfirmationClaim := func(r *http.Request) (CertificateBoundClaims, error) {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			return nil, err
		}
		token, err := jwt.ParseWithClaims(
			cookie.Value,
			&user{},
			func(token *jwt.Token) (any, error) {
				return []byte(jwtSigner), nil
			},
		)
		if err != nil {
			return nil, err
		}
		return token.Claims.(*user), nil
	}

	type args struct {
		cb   func(r *http.Request) (CertificateBoundClaims, error)
		opts []Options
	}
	type err struct {
		statusCode int
		message    string
	}
	tests := []struct {
		name              string
		args              args
		wantErr           *err
		enableRogueClient bool
	}{
		{
			name: "ok",
			args: args{
				cb:   getConfirmationClaim,
				opts: []Options{WithSkipPaths([]string{loginPath})},
			},
		},
		{
			name: "ko cb returns error",
			args: args{
				cb: func(r *http.Request) (CertificateBoundClaims, error) {
					return nil, newError("cb error", jwt.ErrSignatureInvalid)
				},
				opts: []Options{WithSkipPaths([]string{loginPath})},
			},
			wantErr: &err{
				statusCode: http.StatusBadRequest,
				message:    ErrGetCertificateBoundClaims,
			},
		},
		{
			name: "ko stolen cookie",
			args: args{
				cb:   getConfirmationClaim,
				opts: []Options{WithSkipPaths([]string{loginPath})},
			},
			enableRogueClient: true,
			wantErr: &err{
				statusCode: http.StatusForbidden,
				message:    ErrCbcChallengeFailed,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := setupMiddlewareServer(t, string(jwtSigner))
			// add middleware to the server
			server.Config.Handler = CertificateBoundCookieMiddleware(tt.args.cb, tt.args.opts...)(server.Config.Handler)
			server.StartTLS()
			defer server.Close()

			client := setupClient(t)
			loginURL, err := url.Parse(server.URL + loginPath)
			require.NoError(t, err)

			loginRsp, err := client.Get(loginURL.String())
			require.NoError(t, err, "Failed to make login request")
			require.Equal(t, http.StatusOK, loginRsp.StatusCode)
			loginRsp.Body.Close()

			protectedURL, err := url.Parse(server.URL + protectedPath)
			require.NoError(t, err)

			var (
				protectedRsp *http.Response
				errProtected error
			)
			if tt.enableRogueClient {
				rogueClient := setupClient(t)
				rogueClient.Jar = client.Jar // Use the same cookie jar to simulate stolen cookie
				protectedRsp, errProtected = rogueClient.Get(protectedURL.String())
			} else {
				protectedRsp, errProtected = client.Get(protectedURL.String())
			}

			require.NoError(t, errProtected, "Failed to make protected request")
			defer protectedRsp.Body.Close()

			if tt.wantErr != nil {
				require.Equal(t, tt.wantErr.statusCode, protectedRsp.StatusCode)
				b, err := io.ReadAll(protectedRsp.Body)
				require.NoError(t, err, "Failed to read response body")
				require.Equal(t, tt.wantErr.message, strings.Trim(string(b), "\n"), "Expected error message in response body")
			} else {
				require.NoError(t, err, "Failed to make protected request")
				require.Equal(t, http.StatusOK, protectedRsp.StatusCode)
			}
		})
	}
}

func setupMiddlewareServer(t *testing.T, jwtSigner ...string) *httptest.Server {
	var signer []byte
	if len(jwtSigner) > 0 {
		signer = []byte(jwtSigner[0])
	} else {
		signer = []byte("secret")
	}

	fn := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case loginPath:
			cbc, err := Create(r.TLS.PeerCertificates[0], johndoeClaims)
			if err != nil {
				require.NoError(t, err, "Failed to create JWT")
			}
			cookie := &http.Cookie{
				Name:     cookieName,
				Value:    createJWT(t, cbc, signer),
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   60, // 1 minute for testing purposes
			}
			http.SetCookie(w, cookie)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Cookie set"))
		case protectedPath:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		}
	}
	return setupServer(t, fn)
}
