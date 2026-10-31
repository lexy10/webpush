package webpush

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// tokenLifetime keeps VAPID tokens well inside the 24-hour ceiling of RFC 8292.
const tokenLifetime = 12 * time.Hour

var jwtHeader = b64.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`))

// authorization builds the RFC 8292 header value for a push endpoint:
// "vapid t=<ES256 JWT>, k=<public key>".
func (k *Keys) authorization(endpoint, subject string, now time.Time) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Sub string `json:"sub"`
	}{u.Scheme + "://" + u.Host, now.Add(tokenLifetime).Unix(), subject})
	if err != nil {
		return "", err
	}
	input := jwtHeader + "." + b64.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.private, digest[:])
	if err != nil {
		return "", fmt.Errorf("webpush: sign VAPID token: %w", err)
	}
	// JWS ES256 signatures are the fixed-width concatenation r || s, not ASN.1.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return "vapid t=" + input + "." + b64.EncodeToString(sig) + ", k=" + k.public, nil
}
