package main

import (
	"encoding/json"
	"log"

	webpush "github.com/SherClockHolmes/webpush-go"
)

const (
	subscription    = ``
	vapidPublicKey  = ""
	vapidPrivateKey = ""
)

func main() {
	// Decode subscription
	s := &webpush.Subscription{}
	if err := json.Unmarshal([]byte(subscription), s); err != nil {
		log.Fatalf("unmarshaling subscription: %s", err)
	}
	if s.Endpoint == "" {
		log.Fatalf("subscription contains no endpoint field")
	}

	// Send Notification
	resp, err := webpush.SendNotification([]byte("Test"), s, &webpush.Options{
		Subscriber:      "example@example.com", // Do not include "mailto:"
		VAPIDPublicKey:  vapidPublicKey,
		VAPIDPrivateKey: vapidPrivateKey,
		TTL:             30,
	})
	if err != nil {
		log.Fatalf("sending notification: %s", err)
	}
	defer resp.Body.Close()
}
