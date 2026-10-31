// Package webpush sends Web Push messages to browsers and installed web apps.
//
// It implements VAPID application-server authentication (RFC 8292) and
// aes128gcm payload encryption (RFC 8291, RFC 8188) on top of the Go standard
// library, with no third-party dependencies.
package webpush

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultTTL is how long a push service keeps an undelivered message when
// [Options.TTL] is zero.
const DefaultTTL = 24 * time.Hour

// ErrGone means the subscription no longer exists (HTTP 404 or 410). Delete it.
var ErrGone = errors.New("webpush: subscription is gone")

// ErrEndpoint means the subscription endpoint is not an HTTPS URL of a known
// push service. See [WithAnyEndpoint].
var ErrEndpoint = errors.New("webpush: endpoint is not a known push service")

// StatusError is a rejection from the push service other than [ErrGone].
type StatusError struct {
	StatusCode int
	Body       string
	// RetryAfter is set when the push service asked the sender to back off.
	RetryAfter time.Duration
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("webpush: push service returned %d", e.StatusCode)
	}
	return fmt.Sprintf("webpush: push service returned %d: %s", e.StatusCode, e.Body)
}

// Subscription is a browser's PushSubscription, as produced by
// JSON.stringify(subscription) in the page.
type Subscription struct {
	Endpoint string           `json:"endpoint"`
	Keys     SubscriptionKeys `json:"keys"`
}

// SubscriptionKeys are the subscriber's public key and authentication secret.
type SubscriptionKeys struct {
	P256dh string `json:"p256dh"`
	Auth   string `json:"auth"`
}

// Urgency hints how quickly the device should be woken (RFC 8030, section 5.3).
type Urgency string

const (
	UrgencyVeryLow Urgency = "very-low"
	UrgencyLow     Urgency = "low"
	UrgencyNormal  Urgency = "normal"
	UrgencyHigh    Urgency = "high"
)

// Options control the delivery of one message.
type Options struct {
	// TTL is how long the push service keeps the message for an offline
	// device. Zero means DefaultTTL.
	TTL time.Duration
	// Urgency is sent when set.
	Urgency Urgency
	// Topic replaces an undelivered message with the same topic. At most 32
	// characters from the base64url alphabet.
	Topic string
}

// Client sends messages signed with one VAPID identity. It is safe for
// concurrent use.
type Client struct {
	keys        *Keys
	subject     string
	http        *http.Client
	anyEndpoint bool
	now         func() time.Time
}

// ClientOption configures a [Client].
type ClientOption func(*Client)

// WithHTTPClient sets the HTTP client used to reach push services.
func WithHTTPClient(c *http.Client) ClientOption {
	return func(cl *Client) { cl.http = c }
}

// WithAnyEndpoint disables the push-service allowlist. Endpoints come from
// browsers, so without the allowlist a hostile subscriber can make the server
// send requests to any URL; enable this only for tests or private services.
func WithAnyEndpoint() ClientOption {
	return func(cl *Client) { cl.anyEndpoint = true }
}

// NewClient creates a client. subject identifies the sender to push services
// and must be a "mailto:" or "https:" URI.
func NewClient(keys *Keys, subject string, opts ...ClientOption) (*Client, error) {
	if keys == nil {
		return nil, errors.New("webpush: keys are required")
	}
	if !strings.HasPrefix(subject, "mailto:") && !strings.HasPrefix(subject, "https://") {
		return nil, errors.New(`webpush: subject must start with "mailto:" or "https://"`)
	}
	c := &Client{
		keys:    keys,
		subject: subject,
		http:    &http.Client{Timeout: 15 * time.Second},
		now:     time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Send encrypts payload for the subscription and delivers it. It returns
// [ErrGone] when the subscription should be deleted, [*StatusError] for other
// rejections, and nil once the push service has accepted the message.
func (c *Client) Send(ctx context.Context, sub Subscription, payload []byte, o Options) error {
	if !c.anyEndpoint && !KnownEndpoint(sub.Endpoint) {
		return ErrEndpoint
	}
	if !validTopic(o.Topic) {
		return errors.New("webpush: topic must be at most 32 base64url characters")
	}
	body, err := Encrypt(payload, sub.Keys.P256dh, sub.Keys.Auth)
	if err != nil {
		return err
	}
	authz, err := c.keys.authorization(sub.Endpoint, c.subject, c.now())
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ttl := o.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	req.Header.Set("Authorization", authz)
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("TTL", strconv.FormatInt(int64(ttl/time.Second), 10))
	if o.Urgency != "" {
		req.Header.Set("Urgency", string(o.Urgency))
	}
	if o.Topic != "" {
		req.Header.Set("Topic", o.Topic)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	detail, _ := io.ReadAll(io.LimitReader(res.Body, 1024))

	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		return nil
	case res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusGone:
		return ErrGone
	default:
		return &StatusError{
			StatusCode: res.StatusCode,
			Body:       strings.TrimSpace(string(detail)),
			RetryAfter: retryAfter(res.Header.Get("Retry-After"), c.now()),
		}
	}
}

func retryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

func validTopic(t string) bool {
	if len(t) > 32 {
		return false
	}
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// pushServices are the hosts browsers hand out as subscription endpoints.
var pushServices = []string{
	"fcm.googleapis.com",                // Chrome, Edge on Android, Opera
	"android.googleapis.com",            // older Chrome
	"updates.push.services.mozilla.com", // Firefox
	"push.services.mozilla.com",
	"web.push.apple.com", // Safari on macOS and iOS
	"notify.windows.com", // Edge on Windows
}

// KnownEndpoint reports whether endpoint is an HTTPS URL on a browser push
// service, without credentials.
func KnownEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range pushServices {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}
