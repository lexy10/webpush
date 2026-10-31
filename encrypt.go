package webpush

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// recordSize is the aes128gcm record size written into the header. The
	// whole message fits in one record.
	recordSize = 4096
	headerSize = 16 + 4 + 1 + 65
	tagSize    = 16

	// MaxPayload is the largest plaintext a push service is required to
	// accept: 4096 octets of body, less the header, delimiter and GCM tag
	// (RFC 8291, section 4).
	MaxPayload = recordSize - headerSize - 1 - tagSize
)

// ErrPayloadTooLarge means the payload exceeds [MaxPayload].
var ErrPayloadTooLarge = errors.New("webpush: payload exceeds 3993 bytes")

// Encrypt seals payload for one subscriber using the aes128gcm content coding
// (RFC 8188) with the Web Push key derivation (RFC 8291). p256dh and auth are
// the subscription's keys as the browser reports them.
func Encrypt(payload []byte, p256dh, auth string) ([]byte, error) {
	uaPub, err := decodeB64(p256dh)
	if err != nil {
		return nil, fmt.Errorf("webpush: p256dh: %w", err)
	}
	secret, err := decodeB64(auth)
	if err != nil {
		return nil, fmt.Errorf("webpush: auth: %w", err)
	}
	as, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return seal(payload, uaPub, secret, as, salt)
}

// seal is Encrypt with the ephemeral key and salt supplied, so the RFC's
// published vectors can be reproduced exactly.
func seal(payload, uaPub, authSecret []byte, as *ecdh.PrivateKey, salt []byte) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, ErrPayloadTooLarge
	}
	if len(authSecret) != 16 {
		return nil, fmt.Errorf("webpush: auth secret is %d bytes, want 16", len(authSecret))
	}
	// NewPublicKey rejects points that are not on P-256, as section 7 requires.
	ua, err := ecdh.P256().NewPublicKey(uaPub)
	if err != nil {
		return nil, fmt.Errorf("webpush: p256dh: %w", err)
	}
	shared, err := as.ECDH(ua)
	if err != nil {
		return nil, err
	}
	asPub := as.PublicKey().Bytes()

	// IKM = HKDF(auth_secret, ecdh_secret, "WebPush: info" || 0x00 || ua_public || as_public, 32)
	prkKey, err := hkdf.Extract(sha256.New, shared, authSecret)
	if err != nil {
		return nil, err
	}
	keyInfo := make([]byte, 0, 14+65+65)
	keyInfo = append(keyInfo, "WebPush: info\x00"...)
	keyInfo = append(keyInfo, uaPub...)
	keyInfo = append(keyInfo, asPub...)
	ikm, err := hkdf.Expand(sha256.New, prkKey, string(keyInfo), 32)
	if err != nil {
		return nil, err
	}

	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil, err
	}
	cek, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	out := make([]byte, headerSize, headerSize+len(payload)+1+tagSize)
	copy(out, salt)
	binary.BigEndian.PutUint32(out[16:20], recordSize)
	out[20] = byte(len(asPub))
	copy(out[21:], asPub)

	// A single, final record: plaintext followed by the 0x02 delimiter.
	record := make([]byte, 0, len(payload)+1)
	record = append(record, payload...)
	record = append(record, 0x02)
	return gcm.Seal(out, nonce, record, nil), nil
}
