package webpush

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// Urgency indicates to the push service how important a message is to the user.
// This can be used by the push service to help conserve the battery life of a user's device
// by only waking up for important messages when battery is low.
type Urgency string

const (
	// UrgencyVeryLow requires device state: on power and Wi-Fi
	UrgencyVeryLow Urgency = "very-low"
	// UrgencyLow requires device state: on either power or Wi-Fi
	UrgencyLow Urgency = "low"
	// UrgencyNormal excludes device state: low battery
	UrgencyNormal Urgency = "normal"
	// UrgencyHigh admits device state: low battery
	UrgencyHigh Urgency = "high"
)

var saltFunc = func() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return salt, err
	}

	return salt, nil
}

// HTTPClient is an exposed interface to pass in custom http.Client
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Options are config and extra params needed to send a notification
type Options struct {
	HTTPClient      HTTPClient // Will replace with *http.Client by default if not included
	Subscriber      string     // Sub in VAPID JWT token
	Topic           string     // Set the Topic header to collapse a pending messages (Optional)
	TTL             int        // Set the TTL on the endpoint POST request
	Urgency         Urgency    // Set the Urgency header to change a message priority (Optional)
	VAPIDPrivateKey string     // Used to sign VAPID JWT token
	// Used for Authorization in older Chromium browsers:
	// https://web-push-book.gauntface.com/chapter-06/01-non-standards-browsers/#what-is-gcm_sender_id
	LegacyGCMAuthorization string
}

// Keys are the base64 encoded values from PushSubscription.getKey()
type Keys struct {
	Auth   string `json:"auth"`
	P256dh string `json:"p256dh"`
}

// Subscription represents a PushSubscription object from the Push API
type Subscription struct {
	Endpoint string `json:"endpoint"`
	Keys     Keys   `json:"keys"`
}

// SendNotification sends a push notification to a subscriptions endpoint
// Follows the Message Encryption for Web Push, and VAPID protocols
func SendNotification(message []byte, s *Subscription, options *Options) (*http.Response, error) {
	// Decode auth and p256
	clientAuthSecret, err := decodeSubscriptionKey(s.Keys.Auth)
	if err != nil {
		return nil, err
	}

	clientPublicKey, err := decodeSubscriptionKey(s.Keys.P256dh)
	if err != nil {
		return nil, err
	}

	// Generate 16 byte salt
	salt, err := saltFunc()
	if err != nil {
		return nil, err
	}

	// P256 curve
	curve := elliptic.P256()

	// Generate the public / private key pair
	privateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	publicKey := elliptic.Marshal(curve, x, y)

	// Shared secret
	publicKeyX, publicKeyY := elliptic.Unmarshal(curve, clientPublicKey)
	if publicKeyX == nil {
		return nil, errors.New("Unmarshal Error: Public key is not a valid point on the curve")
	}

	sx, _ := curve.ScalarMult(publicKeyX, publicKeyY, privateKey)
	sharedSecret := sx.Bytes()

	// HKDF
	hash := sha256.New
	info := []byte("Content-Encoding: auth\x00")

	// Create the key derivation function
	prkHKDF := hkdf.New(hash, sharedSecret, clientAuthSecret, info)
	prk, err := getHKDFKey(prkHKDF, 32)
	if err != nil {
		return nil, err
	}

	// Derive Content Encryption Key
	contentEncryptionKeyInfo := getInfo([]byte("aesgcm"), clientPublicKey, publicKey)
	contentHKDF := hkdf.New(hash, prk, salt, contentEncryptionKeyInfo)
	contentEncryptionKey, err := getHKDFKey(contentHKDF, 16)
	if err != nil {
		return nil, err
	}

	// Derive the Nonce
	nonceInfo := getInfo([]byte("nonce"), clientPublicKey, publicKey)
	nonceHKDF := hkdf.New(hash, prk, salt, nonceInfo)
	nonce, err := getHKDFKey(nonceHKDF, 12)
	if err != nil {
		return nil, err
	}

	// Cipher
	c, err := aes.NewCipher(contentEncryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// Padding
	padding := make([]byte, 2)
	plaintext := append(padding, message...)

	// Encrypt
	ciphertext := gcm.Seal([]byte{}, nonce, plaintext, nil)

	// POST request
	req, err := http.NewRequest("POST", s.Endpoint, bytes.NewReader(ciphertext))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Encryption", fmt.Sprintf("salt=%s", base64.RawURLEncoding.EncodeToString(salt)))
	req.Header.Set("Crypto-Key", fmt.Sprintf("dh=%s", base64.RawURLEncoding.EncodeToString(publicKey)))
	req.Header.Set("Content-Encoding", "aesgcm")
	req.Header.Set("TTL", strconv.Itoa(options.TTL))

	// Сhecking the optional headers
	if isValidUrgency(options.Urgency) {
		req.Header.Set("Urgency", string(options.Urgency))
	}
	if len(options.Topic) > 0 {
		req.Header.Set("Topic", options.Topic)
	}

	if len(options.LegacyGCMAuthorization) > 0 && strings.HasPrefix(s.Endpoint, "https://android.googleapis.com/gcm/send") {
		// Support older Chromium versions which don't yet support VAPID
		req.Header.Set("Authorization", fmt.Sprintf("key=%s", options.LegacyGCMAuthorization))
	} else {
		// Set VAPID headers
		err = vapid(req, s, options)
		if err != nil {
			return nil, err
		}
	}

	// Send the request
	var client HTTPClient
	if options.HTTPClient != nil {
		client = options.HTTPClient
	} else {
		client = &http.Client{}
	}

	resp, err := client.Do(req)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// decodes a base64 subscription key.
// if necessary, add "=" padding to the key for URL decode
func decodeSubscriptionKey(key string) ([]byte, error) {
	// "=" padding
	buf := bytes.NewBufferString(key)
	if rem := len(key) % 4; rem != 0 {
		buf.WriteString(strings.Repeat("=", 4-rem))
	}

	bytes, err := base64.StdEncoding.DecodeString(buf.String())
	if err == nil {
		return bytes, nil
	}
	return base64.URLEncoding.DecodeString(buf.String())
}

// Returns a key of length "length" given an hkdf function
func getHKDFKey(hkdf io.Reader, length int) ([]byte, error) {
	key := make([]byte, length)
	n, err := io.ReadFull(hkdf, key)
	if n != len(key) || err != nil {
		return key, err
	}

	return key, nil
}

// Helper for content encryption
func getKeyInfo(key []byte) []byte {
	length := uint16(len(key))
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, length)

	var info bytes.Buffer
	info.Write(buf)
	info.Write(key)
	return info.Bytes()
}

// Helper for content encryption
func getInfo(infoType, clientPublicKey, serverPublicKey []byte) []byte {
	var info bytes.Buffer
	info.Write([]byte("Content-Encoding: "))
	info.Write(infoType)
	info.WriteByte(0)
	info.Write([]byte("P-256"))
	info.WriteByte(0)
	info.Write(getKeyInfo(clientPublicKey))
	info.Write(getKeyInfo(serverPublicKey))

	return info.Bytes()
}

// Checking allowable values for the urgency header
func isValidUrgency(urgency Urgency) bool {
	switch urgency {
	case UrgencyVeryLow, UrgencyLow, UrgencyNormal, UrgencyHigh:
		return true
	}
	return false
}
