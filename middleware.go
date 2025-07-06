package gocbc

import (
	"net/http"
	"slices"
)

type MiddlewareFn func(next http.Handler) http.Handler

const (
	ErrMissingCertificate        = "Missing certificate in request"
	ErrCbcChallengeFailed        = "Certificate-Bound Cookie challenge failed"
	ErrGetCertificateBoundClaims = "Failed to get Certificate-Bound Claims from request"
)

type options struct {
	skipPaths []string
}

type Options func(o *options) error

func (c *options) apply(opts []Options) error {
	for _, fn := range opts {
		if err := fn(c); err != nil {
			return err
		}
	}
	return nil
}

func WithSkipPaths(paths []string) Options {
	return func(o *options) error {
		o.skipPaths = paths
		return nil
	}
}

func CertificateBoundCookieMiddleware(cb func(r *http.Request) (CertificateBoundClaims, error), opts ...Options) MiddlewareFn {
	o := &options{}
	if err := o.apply(opts); err != nil {
		panic("failed to apply options: " + err.Error())
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(o.skipPaths) > 0 {
				if slices.Contains(o.skipPaths, r.URL.Path) {
					next.ServeHTTP(w, r)
					return
				}
			}
			cert := GetCertificateFromRequest(r)
			if cert == nil {
				http.Error(w, ErrMissingCertificate, http.StatusBadRequest)
				return
			}

			claims, err := cb(r)
			if err != nil {
				http.Error(w, ErrGetCertificateBoundClaims, http.StatusBadRequest)
				return
			}

			if err := Verify(cert, claims); err != nil {
				http.Error(w, ErrCbcChallengeFailed, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
