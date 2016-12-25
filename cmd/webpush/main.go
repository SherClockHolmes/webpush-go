package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"

	webpush "github.com/sherclockholmes/webpush-go"
)

const (
	vapidPrivateKey = "<YOUR VAPID PRIVATE KEY>"
)

func main() {
	subJSON := `{<YOUR SUBSCRIPTION JSON>}`

	// Decode subscription
	s := webpush.Subscription{}
	if err := json.NewDecoder(bytes.NewBufferString(subJSON)).Decode(&s); err != nil {
		log.Fatal(err)
	}

	// Send Notification
	resp, err := webpush.SendNotification([]byte("Test"), &s, &webpush.Options{
		Subscriber:      "mailto:<EMAIL@EXAMPLE.COM>",
		TTL:             60,
		VAPIDPrivateKey: vapidPrivateKey,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Raw response from endpoint
	log.Println(resp.StatusCode)

	content, _ := ioutil.ReadAll(resp.Body)
	log.Println(string(content))

	resp.Body.Close()
}
