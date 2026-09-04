package auth

import (
	"time"

	pkgauth "github.com/violetaini/chitanda/pkg/auth"
)

type ReplayCache = pkgauth.ReplayCache

const (
	MaxClockSkew = pkgauth.MaxClockSkew
	AuthDomainV2 = pkgauth.AuthDomainV2
)

func NewReplayCache() *ReplayCache {
	return pkgauth.NewReplayCache()
}

func OpenReplayCache(path string, now time.Time) (*ReplayCache, error) {
	return pkgauth.OpenReplayCache(path, now)
}

func LoadPSK(path string) ([]byte, error) {
	return pkgauth.LoadPSK(path)
}

func Signature(psk []byte, mode, method, path, target, timestamp, nonce string) string {
	return pkgauth.Signature(psk, mode, method, path, target, timestamp, nonce)
}

func Verify(psk []byte, mode, method, path, target, timestamp, nonce, signature string, now time.Time) bool {
	return pkgauth.Verify(psk, mode, method, path, target, timestamp, nonce, signature, now)
}
