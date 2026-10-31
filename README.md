# webpush

[![CI](https://github.com/lexy10/webpush/actions/workflows/ci.yml/badge.svg)](https://github.com/lexy10/webpush/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/lexy10/webpush.svg)](https://pkg.go.dev/github.com/lexy10/webpush)

Web Push for Go with **zero dependencies**. VAPID authentication ([RFC 8292]) and aes128gcm payload encryption ([RFC 8291], [RFC 8188]) built on the standard library alone, and verified byte-for-byte against the RFC's published test vector.

- **No third-party code.** ECDH, HKDF, AES-GCM and ES256 signing all come from `crypto/*`.
- **Spec-exact.** The test suite reproduces the worked example in RFC 8291 §5 exactly.
- **Safe by default.** Endpoints come from browsers, so the client only posts to known push services unless you opt out — no server-side request forgery through a crafted subscription.
- **Errors you can act on.** `ErrGone` tells you to delete a subscription; `*StatusError` carries the status, body and `Retry-After`.

Requires Go 1.25 or later.

```sh
go get github.com/lexy10/webpush
```

## Usage

### 1. Generate a VAPID key pair once

```sh
go run github.com/lexy10/webpush/cmd/vapidkeys
```

Keep `VAPID_PRIVATE_KEY` secret. Give `VAPID_PUBLIC_KEY` to the browser.

### 2. Subscribe in the browser

```js
const registration = await navigator.serviceWorker.register("/sw.js");
const subscription = await registration.pushManager.subscribe({
  userVisibleOnly: true,
  applicationServerKey: VAPID_PUBLIC_KEY, // base64url string
});
await fetch("/api/push/subscribe", { method: "POST", body: JSON.stringify(subscription) });
```

```js
// sw.js
self.addEventListener("push", (event) => {
  const data = event.data.json();
  event.waitUntil(self.registration.showNotification(data.title, { body: data.body }));
});
```

### 3. Send from Go

```go
keys, err := webpush.ParseKeys(os.Getenv("VAPID_PRIVATE_KEY"))
if err != nil {
	return err
}
client, err := webpush.NewClient(keys, "mailto:ops@example.com")
if err != nil {
	return err
}

var sub webpush.Subscription // the JSON the browser posted
if err := json.Unmarshal(body, &sub); err != nil {
	return err
}

err = client.Send(ctx, sub, []byte(`{"title":"Order ready","body":"Table 4"}`), webpush.Options{
	TTL:     10 * time.Minute,
	Urgency: webpush.UrgencyHigh,
	Topic:   "order-42", // replaces an undelivered message with the same topic
})

var status *webpush.StatusError
switch {
case errors.Is(err, webpush.ErrGone):
	// The user revoked permission or the subscription expired: delete it.
case errors.As(err, &status) && status.RetryAfter > 0:
	// Throttled: try again after status.RetryAfter.
case err != nil:
	return err
}
```

## API

| | |
|---|---|
| `GenerateKeys()`, `ParseKeys(private)` | Create or load a P-256 VAPID key pair. |
| `NewClient(keys, subject, ...opts)` | A sender identity. `subject` is a `mailto:` or `https:` contact for push services. |
| `WithHTTPClient(c)` | Use your own `*http.Client` (timeouts, proxies, tracing). |
| `WithAnyEndpoint()` | Disable the push-service allowlist. Only for tests or private push services. |
| `(*Client).Send(ctx, sub, payload, opts)` | Encrypt and deliver one message. |
| `Encrypt(payload, p256dh, auth)` | The RFC 8291 encryption alone, for other transports. |
| `KnownEndpoint(url)` | Whether a URL belongs to a browser push service. |
| `MaxPayload` | 3993 bytes — the most a push service must accept after encryption overhead. |

## How it works

1. **Key agreement.** A fresh P-256 key pair is generated per message and combined with the subscriber's `p256dh` key using ECDH.
2. **Key derivation.** HKDF-SHA-256 mixes the shared secret with the subscriber's `auth` secret and both public keys, then a random 16-byte salt, to derive a 128-bit content key and 96-bit nonce.
3. **Encryption.** The payload plus a `0x02` final-record delimiter is sealed with AES-128-GCM and prefixed with the aes128gcm header: salt, record size, and the ephemeral public key.
4. **Authentication.** An ES256 JWT scoped to the push service's origin, valid for 12 hours, goes in `Authorization: vapid t=…, k=…`.

## Origin

Extracted from the mobile alerting path of ClarttCapital, a Go trading engine, where it delivers fills and risk halts to a phone without a native app.

## License

[MIT](LICENSE)

[RFC 8188]: https://www.rfc-editor.org/rfc/rfc8188
[RFC 8291]: https://www.rfc-editor.org/rfc/rfc8291
[RFC 8292]: https://www.rfc-editor.org/rfc/rfc8292
