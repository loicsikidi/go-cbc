package gocbc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestExample(t *testing.T) {
	server := setupExampleServer(t)
	server.StartTLS()
	defer server.Close()

	t.Run("ok", func(t *testing.T) {
		client := setupClient(t)

		loginURL, err := url.Parse(server.URL + loginPath)
		require.NoError(t, err)

		loginRsp, err := client.Get(loginURL.String())
		require.NoError(t, err, "Failed to make login request")
		require.Equal(t, http.StatusOK, loginRsp.StatusCode)
		loginRsp.Body.Close()

		// Check that the cookie is stored in jar object
		cookies := client.Jar.Cookies(loginURL)
		require.Len(t, cookies, 1, "Expected 1 cookie to be stored")
		require.Equal(t, cookieName, cookies[0].Name)
		require.NotEmpty(t, cookies[0].Value, "Expected cookie value to be set")

		protectedURL, err := url.Parse(server.URL + protectedPath)
		require.NoError(t, err)

		protectedRsp, err := client.Get(protectedURL.String())
		require.NoError(t, err, "Failed to make protected request")
		require.Equal(t, http.StatusOK, protectedRsp.StatusCode)
		protectedRsp.Body.Close()

		require.Equal(t, protectedRsp.StatusCode, http.StatusOK, "Expected status OK on protected request")
	})
	t.Run("ko - stolen cookie", func(t *testing.T) {
		client := setupClient(t)

		loginURL, err := url.Parse(server.URL + loginPath)
		require.NoError(t, err)

		loginRsp, err := client.Get(loginURL.String())
		require.NoError(t, err, "Failed to make login request")
		require.Equal(t, http.StatusOK, loginRsp.StatusCode)
		loginRsp.Body.Close()

		rogueClient := setupClient(t)

		rogueClient.Jar = client.Jar // Use the same cookie jar to simulate stolen cookie

		protectedURL, err := url.Parse(server.URL + protectedPath)
		require.NoError(t, err)

		protectedRsp, err := rogueClient.Get(protectedURL.String())
		require.NoError(t, err, "Failed to make protected request")
		require.Equal(t, http.StatusForbidden, protectedRsp.StatusCode)
		defer protectedRsp.Body.Close()

		bodyRsp, err := io.ReadAll(protectedRsp.Body)
		require.NoError(t, err, "Failed to read response body")

		require.Equal(t, "stolen cookie", string(bodyRsp), "Expected forbidden response for stolen cookie")
	})

}

func setupExampleServer(t *testing.T) *httptest.Server {
	jwtSigner := []byte("secret")

	fn := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case loginPath:
			cbc, err := Create(r.TLS.PeerCertificates[0], johndoeClaims)
			if err != nil {
				require.NoError(t, err, "Failed to create JWT")
			}

			cookie := &http.Cookie{
				Name:     cookieName,
				Value:    createJWT(t, cbc, jwtSigner),
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   3600, // 1 hour
			}
			http.SetCookie(w, cookie)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Cookie set"))
		case protectedPath:
			cookie, err := r.Cookie(cookieName)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("No cookie found"))
				return
			}
			require.NotEmpty(t, cookie.Value, "Expected cookie to be present")
			token, err := jwt.ParseWithClaims(
				cookie.Value,
				&user{},
				func(token *jwt.Token) (any, error) {
					return jwtSigner, nil
				},
			)
			if err := Verify(r.TLS.PeerCertificates[0], token.Claims.(*user)); err != nil {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("stolen cookie"))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Cookie received correctly"))
			}
		}
	}
	return setupServer(t, fn)
}
