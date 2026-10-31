// Command vapidkeys prints a new VAPID key pair.
package main

import (
	"fmt"
	"log"

	"github.com/lexy10/webpush"
)

func main() {
	keys, err := webpush.GenerateKeys()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("VAPID_PRIVATE_KEY=%s\nVAPID_PUBLIC_KEY=%s\n", keys.PrivateKey(), keys.PublicKey())
}
