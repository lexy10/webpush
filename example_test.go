package webpush_test

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"

	"github.com/lexy10/webpush"
)

func ExampleClient_Send() {
	keys, err := webpush.ParseKeys(os.Getenv("VAPID_PRIVATE_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	client, err := webpush.NewClient(keys, "mailto:ops@example.com")
	if err != nil {
		log.Fatal(err)
	}

	// The JSON the page posted after calling pushManager.subscribe().
	var sub webpush.Subscription
	if err := json.Unmarshal([]byte(os.Getenv("SUBSCRIPTION")), &sub); err != nil {
		log.Fatal(err)
	}

	err = client.Send(context.Background(), sub, []byte(`{"title":"Order ready"}`), webpush.Options{
		Urgency: webpush.UrgencyHigh,
		Topic:   "order-42",
	})
	if errors.Is(err, webpush.ErrGone) {
		// Delete the subscription: the user revoked permission or it expired.
	} else if err != nil {
		log.Print(err)
	}
}
