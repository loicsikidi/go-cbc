package cbc

import (
	"crypto/x509"
	"net/http"
)

type GetCertificateFn func() *x509.Certificate

func GetCertificateFromRequestFn(r *http.Request) GetCertificateFn {
	return func() *x509.Certificate {
		return GetCertificateFromRequest(r)
	}
}

func GetCertificateFromRequest(r *http.Request) *x509.Certificate {
	if r != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0] // leaf certificate
	}
	return nil
}
