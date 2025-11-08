package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	webpush "github.com/SherClockHolmes/webpush-go"
)

var (
	vapidPrivateKey string
	vapidPublicKey  string
)

// VAPIDKeys holds the VAPID private and public keys.
type VAPIDKeys struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// SendNotificationRequest is the request body for the /send_notification endpoint.
type SendNotificationRequest struct {
	Subscription webpush.Subscription `json:"subscription"`
	AuthScheme   webpush.AuthScheme   `json:"authScheme"`
}


func main() {
	// Check for VAPID keys file
	_, err := os.Stat("vapid_keys.json")
	if os.IsNotExist(err) {
		log.Println("VAPID keys file not found, generating new ones...")
		newPrivateKey, newPublicKey, err := webpush.GenerateVAPIDKeys()
		if err != nil {
			log.Fatalf("Failed to generate VAPID keys: %v", err)
		}
		vapidPrivateKey = newPrivateKey
		vapidPublicKey = newPublicKey

		keys := VAPIDKeys{
			PrivateKey: vapidPrivateKey,
			PublicKey:  vapidPublicKey,
		}
		jsonBytes, err := json.Marshal(keys)
		if err != nil {
			log.Fatalf("Failed to marshal keys to JSON: %v", err)
		}

		if err := ioutil.WriteFile("vapid_keys.json", jsonBytes, 0600); err != nil {
			log.Fatalf("Failed to save keys file: %v", err)
		}
		log.Println("New VAPID keys generated and saved.")
	} else {
		log.Println("Loading VAPID keys from file...")
		jsonBytes, err := ioutil.ReadFile("vapid_keys.json")
		if err != nil {
			log.Fatalf("Failed to read keys file: %v", err)
		}

		var keys VAPIDKeys
		if err := json.Unmarshal(jsonBytes, &keys); err != nil {
			log.Fatalf("Failed to unmarshal keys from JSON: %v", err)
		}
		vapidPrivateKey = keys.PrivateKey
		vapidPublicKey = keys.PublicKey
		log.Println("VAPID keys loaded.")
	}

	http.HandleFunc("/vapid_public_key", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(vapidPublicKey))
	})

	http.HandleFunc("/send_notification", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading body: %v", err)
			http.Error(w, "Error reading body", http.StatusInternalServerError)
			return
		}

		var req SendNotificationRequest
		if err := json.Unmarshal(body, &req); err != nil {
			log.Printf("Error unmarshalling request: %v", err)
			http.Error(w, "Error unmarshalling request", http.StatusBadRequest)
			return
		}
		
		// Send Notification
		resp, err := webpush.SendNotification([]byte("Test"), &req.Subscription, &webpush.Options{
			AuthScheme:      req.AuthScheme,
			Subscriber:      "example@example.com", // Do not include "mailto:"
			VAPIDPublicKey:  vapidPublicKey,
			VAPIDPrivateKey: vapidPrivateKey,
			TTL:             30,
		})
		if err != nil {
			log.Printf("Error sending notification: %v", err)
			http.Error(w, "Error sending notification", http.StatusInternalServerError)
			return
		}

		defer resp.Body.Close()

		// Print status code
		fmt.Fprintf(w, "Status: %d", resp.StatusCode)
	})

	http.Handle("/", http.FileServer(http.Dir(".")))

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
