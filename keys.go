package webpush

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

var b64 = base64.RawURLEncoding

// decodeB64 accepts base64url or standard base64, padded or not: browsers,
// SDKs and key generators disagree on the encoding.
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	if b, err := b64.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// Keys is an application server's VAPID key pair on P-256.
type Keys struct {
	private    *ecdsa.PrivateKey
	privateB64 string
	public     string
}

// GenerateKeys creates a new VAPID key pair.
func GenerateKeys() (*Keys, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return newKeys(priv)
}

// ParseKeys loads a key pair from its private key: the 32-byte P-256 scalar,
// base64url-encoded, as returned by [Keys.PrivateKey].
func ParseKeys(private string) (*Keys, error) {
	d, err := decodeB64(private)
	if err != nil {
		return nil, fmt.Errorf("webpush: private key is not base64: %w", err)
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		return nil, fmt.Errorf("webpush: private key: %w", err)
	}
	return newKeys(priv)
}

func newKeys(priv *ecdsa.PrivateKey) (*Keys, error) {
	d, err := priv.Bytes()
	if err != nil {
		return nil, err
	}
	pub, err := priv.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	return &Keys{private: priv, privateB64: b64.EncodeToString(d), public: b64.EncodeToString(pub)}, nil
}

// PublicKey is the uncompressed public key, base64url-encoded. Browsers take
// it as the applicationServerKey when subscribing.
func (k *Keys) PublicKey() string { return k.public }

// PrivateKey is the private scalar, base64url-encoded. Store it as a secret.
func (k *Keys) PrivateKey() string { return k.privateB64 }
