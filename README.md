## Overview

`go-cbc` is a go library which provides a simple interface in order to take advantage of Certificate-Bound 🍪.

> [!WARNING]  
> Certificate-Bound Cookie (aka. CBC) is not a standard.

## Motivation

Certificate-Bound Cookie is strategy (there are others) to address [*cookie thief*](https://cheatsheetseries.owasp.org/cheatsheets/Cookie_Theft_Mitigation_Cheat_Sheet.html) attacks. Today, we're in a rather paradoxical situation where on one hand the login process is more and more robust (eg., 2FA, WebAuthn, etc.), and even if an attacker steals only the password, he/she can't do much with it. On the other hand, if the attacker can steal a valid session cookie instead, it is possible to hijack the user session for the duration of the session lifetime period.

In a nutshell, session cookies are the weakest point and should be protected as much as possible.

This library is inspired by [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html) (*OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens*) which describes how to tie an access token to a TLS client certificate. The idea is to use the same concept but for session cookies!

> [!NOTE]  
> Once upon a time, there was a protocol called [Token binding (RFC 8473)](https://datatracker.ietf.org/doc/html/rfc8473) which was designed to bind a token (eg., OAuth token, http cookie) to a TLS connection. Unfortunately, it was never widely adopted by major web browsers and is now in brain death - which explains why we implement this logc at the application-level.

## Does this library is for you?

Yes, if:
* your application is served in mTLS (mutual TLS) mode
* if your session cookie is represented as a JWT (JSON Web Token)
  * NOTE: this library currently only supports [golang-jwt](https://github.com/golang-jwt/jwt)

## Usage

```go
package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/loicsikidi/go-cbc"
)

const (
	jwtSigner  = "your-secret"
	cookieName = "amazing-session-cookie"
)

// session object
type userSession struct {
	jwt.RegisteredClaims
	cbc.ConfirmationClaim          // MANDATORY: this struct is used to store the certificate binding information
	Username              string   `json:"username"`
	Permissions           []string `json:"permissions"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/protected", protectedHandler)

	// MANDATORY: create the Certificate Bound Cookie middleware
	// The middleware will automatically check that the session cookie is bound to the TLS client certificate
	handler := cbc.CertificateBoundCookieMiddleware(func(r *http.Request) (cbc.CertificateBoundClaims, error) {
		// NOTE: via this callback, you have the responsability to return the session claims
		// which can be stored outside of the cookie (eg., in a database, cache, etc.)
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			return nil, err
		}
		token, err := jwt.ParseWithClaims(
			cookie.Value,
			&userSession{},
			func(token *jwt.Token) (any, error) {
				return []byte(jwtSigner), nil
			},
		)
		if err != nil {
			return nil, err
		}
		return token.Claims.(*userSession), nil
	}, cbc.WithSkipPaths([]string{"/login"}))(mux)

	server := &http.Server{
		Addr:    ":8443",
		Handler: handler,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert, // MANDATORY: enforce mTLS
		},
	}

	if err := server.ListenAndServeTLS("cert.pem", "key.pem"); err != nil && err != http.ErrServerClosed {
		log.Fatal("Server failed to start: ", err)
	} else {
		log.Println("Server started on https://localhost:8443")
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// login process
	// ...
	currentUser := &userSession{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "trusted-idp",
			Subject:   "uuid",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
		Username:    "johndoe",
		Permissions: []string{"read", "write"},
	}

	// MANDATORY: bind the session to the TLS client certificate
	claims, err := cbc.Create(cbc.GetCertificateFromRequest(r), currentUser)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name: cookieName,
		// NOTE: you can store the JWT in a database or cache instead of a cookie and use the cookie only as a reference
		Value:    createJWT(claims, []byte(jwtSigner)),
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600, // 1 hour
	}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Login successful"))
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}
```

### How the magic works 🪄?

As described in the [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html), we are able to link the JWT with the TLS client certificate by adding a `confirmation` claim. This claim contains the SHA-256 hash of the TLS client certificate, which is used to verify afterware the binding.

```jsonc
{
    "iss": "trusted-idp",
    "sub": "uuid",
    "username": "johndoe",
    "permissions": ["read", "write"],
    "cnf": {
        "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2" // SHA-256 hash of the TLS client certificate
    }
}
```

## Contribute

If you want to contribute to this project, feel free to open an issue or a pull request. Any contribution is welcome!

## Alternatives

| Library | Description |
|---------|-------------|
| [Device Bound Session Credentials](https://w3c.github.io/webappsec-dbsc/) (DBSC) | The spec (which is still a draft at time of writing) is available in the *W3C* but it's currently ONLY implemented in Chrome. |
| [OWASP Cookie Theft Mitigation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cookie_Theft_Mitigation_Cheat_Sheet.html) | The document is mainly focus on *cookie theft detection*  |
