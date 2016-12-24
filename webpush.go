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
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// Options are config and extra params needed to send a notification
type Options struct {
	Subscriber      string // Sub in VAPID JWT token
	TTL             int
	VapidPrivateKey string // Used to sign VAPID JWT token
}

// Subscription represents a PushSubscription object from the Push API
type Subscription struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
}

// SendNotification sends a push notification to a subscriptions endpoint
// Follows the Message Encryption for Web Push, and VAPID protocols
func SendNotification(s *Subscription, message []byte, options *Options) (*http.Response, error) {
	// Decode auth and p256
	b64 := base64.RawURLEncoding

	// Chrome bug appends "=" to the end
	clientAuthSecret, err := b64.DecodeString(strings.TrimRight(s.Keys.Auth, "="))
	if err != nil {
		return &http.Response{}, err
	}

	clientPublicKey, err := b64.DecodeString(strings.TrimRight(s.Keys.P256dh, "="))
	if err != nil {
		return &http.Response{}, err
	}

	// Generate 16 byte salt
	salt := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, salt)
	if err != nil {
		return &http.Response{}, err
	}

	// P256 curve
	curve := elliptic.P256()

	// Generate the public / private key pair
	privateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return &http.Response{}, err
	}

	publicKey := elliptic.Marshal(curve, x, y)

	// Shared secret
	publicKeyX, publicKeyY := elliptic.Unmarshal(curve, clientPublicKey)
	if publicKeyY == nil {
		return &http.Response{}, err
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
		return &http.Response{}, err
	}

	// Derive Content Encryption Key
	contentEncryptionKeyInfo := getInfo([]byte("aesgcm"), clientPublicKey, publicKey)
	contentHKDF := hkdf.New(hash, prk, salt, contentEncryptionKeyInfo)
	contentEncryptionKey, err := getHKDFKey(contentHKDF, 16)
	if err != nil {
		return &http.Response{}, err
	}

	// Derive the Nonce
	nonceInfo := getInfo([]byte("nonce"), clientPublicKey, publicKey)
	nonceHKDF := hkdf.New(hash, prk, salt, nonceInfo)
	nonce, err := getHKDFKey(nonceHKDF, 12)
	if err != nil {
		return &http.Response{}, err
	}

	// Cipher
	c, err := aes.NewCipher(contentEncryptionKey)
	if err != nil {
		return &http.Response{}, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return &http.Response{}, err
	}

	// Padding
	padding := make([]byte, 2)
	plaintext := append(padding, message...)

	// Encrypt
	ciphertext := gcm.Seal([]byte{}, nonce, plaintext, nil)

	// POST request
	req, err := http.NewRequest("POST", s.Endpoint, nil)
	if err != nil {
		return &http.Response{}, err
	}

	req.Body = ioutil.NopCloser(bytes.NewReader(ciphertext))
	req.ContentLength = int64(len(ciphertext))

	req.Header.Set("Encryption", fmt.Sprintf("salt=%s", base64.RawURLEncoding.EncodeToString(salt)))
	req.Header.Set("Crypto-Key", fmt.Sprintf("dh=%s", base64.RawURLEncoding.EncodeToString(publicKey)))
	req.Header.Set("Content-Encoding", "aesgcm")
	req.Header.Set("TTL", strconv.Itoa(options.TTL))

	// Set VAPID headers
	err = vapid(s, req, options)
	if err != nil {
		return &http.Response{}, err
	}

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return resp, err
	}

	return resp, nil
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
