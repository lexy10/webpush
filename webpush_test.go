package webpush

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := decodeB64(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The worked example from RFC 8291, section 5 and appendix A.
func TestRFC8291Vector(t *testing.T) {
	plaintext := []byte("When I grow up, I want to be a watermelon")
	asPrivate := mustB64(t, "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")
	uaPublic := mustB64(t, `BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx
		aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4`)
	salt := mustB64(t, "DGv6ra1nlYgDCS1FRnbzlw")
	authSecret := mustB64(t, "BTBZMqHH6r4Tts7J_aSIgg")
	want := mustB64(t, `DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml
		mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT
		pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN`)

	as, err := ecdh.P256().NewPrivateKey(asPrivate)
	if err != nil {
		t.Fatal(err)
	}
	got, err := seal(plaintext, uaPublic, authSecret, as, salt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ciphertext differs from RFC 8291\n got %s\nwant %s", b64.EncodeToString(got), b64.EncodeToString(want))
	}
}

// device is the browser's side of a subscription.
type device struct {
	priv *ecdh.PrivateKey
	auth []byte
}

func newDevice(t *testing.T) device {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	if _, err := rand.Read(auth); err != nil {
		t.Fatal(err)
	}
	return device{priv: priv, auth: auth}
}

func (d device) keys() SubscriptionKeys {
	return SubscriptionKeys{P256dh: b64.EncodeToString(d.priv.PublicKey().Bytes()), Auth: b64.EncodeToString(d.auth)}
}

// decrypt opens a message the way a browser does.
func (d device) decrypt(t *testing.T, body []byte) []byte {
	t.Helper()
	salt, rs, idlen := body[:16], binary.BigEndian.Uint32(body[16:20]), int(body[20])
	if rs != recordSize || idlen != 65 {
		t.Fatalf("header: record size %d, key id length %d", rs, idlen)
	}
	asPub := body[21 : 21+idlen]
	as, err := ecdh.P256().NewPublicKey(asPub)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := d.priv.ECDH(as)
	if err != nil {
		t.Fatal(err)
	}
	prkKey, _ := hkdf.Extract(sha256.New, shared, d.auth)
	ikm, _ := hkdf.Expand(sha256.New, prkKey, "WebPush: info\x00"+string(d.priv.PublicKey().Bytes())+string(asPub), 32)
	prk, _ := hkdf.Extract(sha256.New, ikm, salt)
	cek, _ := hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16)
	nonce, _ := hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	pt, err := gcm.Open(nil, nonce, body[21+idlen:], nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if pt[len(pt)-1] != 0x02 {
		t.Fatalf("missing final-record delimiter")
	}
	return pt[:len(pt)-1]
}

func TestEncryptRoundTrip(t *testing.T) {
	d := newDevice(t)
	msg := []byte(`{"title":"Order ready","body":"Table 4"}`)
	body, err := Encrypt(msg, d.keys().P256dh, d.keys().Auth)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.decrypt(t, body); !bytes.Equal(got, msg) {
		t.Fatalf("round trip: got %q", got)
	}
}

func TestPayloadLimit(t *testing.T) {
	d := newDevice(t)
	body, err := Encrypt(make([]byte, MaxPayload), d.keys().P256dh, d.keys().Auth)
	if err != nil {
		t.Fatalf("max payload rejected: %v", err)
	}
	if len(body) != recordSize {
		t.Fatalf("max payload body is %d bytes, want %d", len(body), recordSize)
	}
	if _, err := Encrypt(make([]byte, MaxPayload+1), d.keys().P256dh, d.keys().Auth); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversized payload: got %v", err)
	}
}

func TestEncryptRejectsBadKeys(t *testing.T) {
	d := newDevice(t)
	offCurve := make([]byte, 65)
	offCurve[0] = 0x04
	if _, err := Encrypt([]byte("x"), b64.EncodeToString(offCurve), d.keys().Auth); err == nil {
		t.Fatal("accepted a public key that is not on P-256")
	}
	if _, err := Encrypt([]byte("x"), d.keys().P256dh, b64.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("accepted a short auth secret")
	}
}

func TestKeysRoundTrip(t *testing.T) {
	k, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseKeys(k.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	if again.PublicKey() != k.PublicKey() {
		t.Fatal("public key changed after parsing the private key")
	}
	if pub := mustB64(t, k.PublicKey()); len(pub) != 65 || pub[0] != 0x04 {
		t.Fatalf("public key is not an uncompressed P-256 point: %d bytes", len(pub))
	}
}

func TestVAPIDToken(t *testing.T) {
	k, _ := GenerateKeys()
	now := time.Unix(1_800_000_000, 0)
	header, err := k.authorization("https://fcm.googleapis.com/fcm/send/abc", "mailto:ops@example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	token, key, ok := strings.Cut(strings.TrimPrefix(header, "vapid t="), ", k=")
	if !ok || key != k.PublicKey() {
		t.Fatalf("header format: %q", header)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}

	sig := mustB64(t, parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if len(sig) != 64 || !ecdsa.Verify(&k.private.PublicKey, digest[:], r, s) {
		t.Fatal("signature does not verify")
	}

	var claims struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(mustB64(t, parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Aud != "https://fcm.googleapis.com" || claims.Sub != "mailto:ops@example.com" {
		t.Fatalf("claims: %+v", claims)
	}
	if claims.Exp != now.Add(tokenLifetime).Unix() {
		t.Fatalf("exp %d", claims.Exp)
	}
}

func TestSend(t *testing.T) {
	d := newDevice(t)
	keys, _ := GenerateKeys()
	status := http.StatusCreated
	var got *http.Request
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		body, _ = io.ReadAll(r.Body)
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "30")
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()

	c, err := NewClient(keys, "https://example.com/contact", WithAnyEndpoint(), WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	sub := Subscription{Endpoint: srv.URL + "/push/1", Keys: d.keys()}
	opts := Options{TTL: 90 * time.Second, Urgency: UrgencyHigh, Topic: "fills"}

	if err := c.Send(context.Background(), sub, []byte("filled"), opts); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"Content-Encoding": "aes128gcm",
		"TTL":              "90",
		"Urgency":          "high",
		"Topic":            "fills",
	} {
		if v := got.Header.Get(name); v != want {
			t.Errorf("%s: got %q, want %q", name, v, want)
		}
	}
	if !strings.HasPrefix(got.Header.Get("Authorization"), "vapid t=") {
		t.Errorf("Authorization: %q", got.Header.Get("Authorization"))
	}
	if msg := d.decrypt(t, body); string(msg) != "filled" {
		t.Errorf("payload: %q", msg)
	}

	if err := c.Send(context.Background(), sub, []byte("x"), Options{}); err != nil || got.Header.Get("TTL") != "86400" {
		t.Errorf("default TTL: err %v, TTL %q", err, got.Header.Get("TTL"))
	}

	for _, code := range []int{http.StatusNotFound, http.StatusGone} {
		status = code
		if err := c.Send(context.Background(), sub, []byte("x"), Options{}); !errors.Is(err, ErrGone) {
			t.Errorf("%d: got %v, want ErrGone", code, err)
		}
	}

	status = http.StatusTooManyRequests
	var se *StatusError
	if err := c.Send(context.Background(), sub, []byte("x"), Options{}); !errors.As(err, &se) || se.RetryAfter != 30*time.Second {
		t.Errorf("429: got %v", err)
	}

	if err := c.Send(context.Background(), sub, []byte("x"), Options{Topic: "not a topic!"}); err == nil {
		t.Error("accepted an invalid topic")
	}
}

func TestSendRefusesUnknownEndpoints(t *testing.T) {
	keys, _ := GenerateKeys()
	c, _ := NewClient(keys, "mailto:ops@example.com")
	sub := Subscription{Endpoint: "http://169.254.169.254/latest/meta-data", Keys: newDevice(t).keys()}
	if err := c.Send(context.Background(), sub, []byte("x"), Options{}); !errors.Is(err, ErrEndpoint) {
		t.Fatalf("got %v, want ErrEndpoint", err)
	}
}

func TestKnownEndpoint(t *testing.T) {
	for endpoint, want := range map[string]bool{
		"https://fcm.googleapis.com/fcm/send/abc":                true,
		"https://updates.push.services.mozilla.com/wpush/v2/abc": true,
		"https://web.push.apple.com/QGuQyavXutnMH":               true,
		"https://wns2-par02p.notify.windows.com/w/?token=abc":    true,
		"http://fcm.googleapis.com/fcm/send/abc":                 false,
		"https://fcm.googleapis.com.evil.example/x":              false,
		"https://user:pass@fcm.googleapis.com/x":                 false,
		"https://example.com/push":                               false,
		"not a url":                                              false,
	} {
		if got := KnownEndpoint(endpoint); got != want {
			t.Errorf("KnownEndpoint(%q) = %v, want %v", endpoint, got, want)
		}
	}
}

func TestNewClientValidatesSubject(t *testing.T) {
	keys, _ := GenerateKeys()
	if _, err := NewClient(keys, "ops@example.com"); err == nil {
		t.Fatal("accepted a subject without mailto: or https:")
	}
	if _, err := NewClient(nil, "mailto:ops@example.com"); err == nil {
		t.Fatal("accepted nil keys")
	}
}
