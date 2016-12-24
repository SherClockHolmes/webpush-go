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

	// Subscription info
	log.Println(s.Endpoint)
	log.Println(s.Keys.Auth)
	log.Println(s.Keys.P256dh)

	// Send Notification
	resp, err := webpush.SendNotification(&s, []byte("Test"), &webpush.Options{
		Subscriber:      "mailto:<EMAIL@EXAMPLE.COM>",
		TTL:             60,
		VapidPrivateKey: vapidPrivateKey,
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
