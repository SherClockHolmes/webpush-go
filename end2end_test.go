package webpush

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/hkdf"
)

func TestEnd2End(t *testing.T) {
	var (
		// the data known to the application server (backend, which uses webpush-go)
		applicationServer struct {
			publicVAPIDKey  string
			privateVAPIDKey string
			subscription    Subscription
		}
		// the data known to the user agent (browser)
		userAgent struct {
			publicVAPIDKey        *ecdsa.PublicKey
			subscriptionKey       *ecdsa.PrivateKey
			authSecret            [16]byte
			subscription          Subscription
			receivedNotifications [][]byte
		}
		// the data known to the push server (which receives push messages on behalf of the user agent, e.g. Firestore)
		pushService struct {
			applicationServerKey  *ecdsa.PublicKey
			receivedNotifications [][]byte
		}

		err error
	)

	// a VAPID key pair for the application server, usually only generated once and reused
	applicationServer.privateVAPIDKey, applicationServer.publicVAPIDKey, err = GenerateVAPIDKeys()
	if err != nil {
		t.Fatalf("generating VAPID keys: %s", err)
	}

	// The application server needs to inform the user agent of the public VAPID key.
	// (We decode it first for ease of use.)
	userAgent.publicVAPIDKey, err = decodeVAPIDPublicKey(applicationServer.publicVAPIDKey)
	if err != nil {
		t.Fatal(err)
	}

	// We need a mock push service for webpush-go to send notifications to.
	var mockPushService *httptest.Server
	mockPushService = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check that there's a valid vapid JWT
		token, err := parseVapidAuthHeader(
			r.Header.Get("Authorization"),
			// by the time this function is called, this value will be set (see PushManager.subscribe() below)
			pushService.applicationServerKey)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprintf(w, "invalid auth: %s", err)
			return
		}
		// verify that the audience matches our URL
		aud := token.Claims.(jwt.MapClaims)["aud"]
		if aud != mockPushService.URL {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprintf(w, "JWT has bad audience, want %q, got %q", mockPushService.URL, aud)
			return
		}
		// RFC8188 only allows for exactly one content encoding
		if contentEncoding := r.Header.Get("Content-Encoding"); contentEncoding != "aes128gcm" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "unsupported Content-Encoding, want %q, got %q", "aes128gcm", contentEncoding)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			// this suggests a broken connection, so log the error instead of sending it back
			t.Errorf("failed to read request body: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// store body for later decoding by user agent
		// (the push service doesn't have the key required for decryption)
		pushService.receivedNotifications = append(pushService.receivedNotifications, body)

		w.WriteHeader(http.StatusAccepted)
	}))
	defer mockPushService.Close()

	// what follows is the equivalent of PushManager.subscribe() in JS
	{
		// the user agent generates its own key pair so it can be sent encrypted messages
		userAgent.subscriptionKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating user agent keys: %s", err)
		}
		// we need the ECDH representation
		ecdhPublicKey, err := userAgent.subscriptionKey.PublicKey.ECDH()
		if err != nil {
			t.Fatalf("converting user agent public key to ECDH: %s", err)
		}
		// generate the shared auth secret
		_, err = rand.Read(userAgent.authSecret[:])
		if err != nil {
			t.Fatalf("generating user agent auth secret: %s", err)
		}
		// the user agent then performs a registration with the push service using that key,
		// while also letting the push service know the application server key to expect.
		pushService.applicationServerKey = userAgent.publicVAPIDKey
		userAgent.subscription = Subscription{
			Keys: Keys{
				Auth:   base64.StdEncoding.EncodeToString(userAgent.authSecret[:]),
				P256dh: base64.StdEncoding.EncodeToString(ecdhPublicKey.Bytes()),
			},
			Endpoint: mockPushService.URL,
		}
	}

	// the user agent sends its subscription to the application server...
	applicationServer.subscription = userAgent.subscription

	// ...and the application server uses the subscription to send a push notification
	sentMessage := "this is our test push notification"
	resp, err := SendNotification([]byte(sentMessage), &applicationServer.subscription, &Options{
		HTTPClient:      mockPushService.Client(),
		VAPIDPublicKey:  applicationServer.publicVAPIDKey,
		VAPIDPrivateKey: applicationServer.privateVAPIDKey,
		Subscriber:      "test@example.com",
	})
	if err != nil {
		t.Fatalf("failed to send notification: %s", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("error closing mock push service response body: %s", err)
		}
	}()
	// check for success
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading mock push service response body: %s", err)
	}
	if resp.StatusCode/100 != 2 {
		t.Errorf("unexpected push service status code %d, body: %s", resp.StatusCode, respBody)
	}

	// the push server should now have received the notification
	if l := len(pushService.receivedNotifications); l != 1 {
		t.Fatalf("Want 1 notification received by push service, got %d", l)
	}
	// the push service then forwards the notification to the user agent
	userAgent.receivedNotifications = pushService.receivedNotifications
	// and the user agent can decrypt them
	receivedMessage, err := decodeNotification(userAgent.receivedNotifications[0], userAgent.authSecret, userAgent.subscriptionKey)
	if err != nil {
		t.Fatalf("error decrypting notification in user agent: %s", err)
	}
	if receivedMessage != sentMessage {
		t.Errorf("Sent notification %q, but got %q", sentMessage, receivedMessage)
	}
}

func decodeVAPIDPublicKey(publicVAPIDKey string) (*ecdsa.PublicKey, error) {
	publicVAPIDKeyBytes, err := base64.RawURLEncoding.DecodeString(publicVAPIDKey)
	if err != nil {
		return nil, fmt.Errorf("base64-decoding public VAPID key: %w", err)
	}
	return decodeECDSAPublicKey(publicVAPIDKeyBytes)
}

func decodeECDSAPublicKey(bytes []byte) (*ecdsa.PublicKey, error) {
	ecdhKey, err := ecdh.P256().NewPublicKey(bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public VAPID key: %w", err)
	}
	res, err := ecdhPublicKeyToECDSA(ecdhKey)
	if err != nil {
		return nil, fmt.Errorf("converting public VAPID key from *ecdh.PublicKey to *ecdsa.PublicKey: %w", err)
	}
	return res, nil
}

func ecdhPublicKeyToECDSA(key *ecdh.PublicKey) (*ecdsa.PublicKey, error) {
	// see https://github.com/golang/go/issues/63963
	rawKey := key.Bytes()
	switch key.Curve() {
	case ecdh.P256():
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(0).SetBytes(rawKey[1:33]),
			Y:     big.NewInt(0).SetBytes(rawKey[33:]),
		}, nil
	case ecdh.P384():
		return &ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     big.NewInt(0).SetBytes(rawKey[1:49]),
			Y:     big.NewInt(0).SetBytes(rawKey[49:]),
		}, nil
	case ecdh.P521():
		return &ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     big.NewInt(0).SetBytes(rawKey[1:67]),
			Y:     big.NewInt(0).SetBytes(rawKey[67:]),
		}, nil
	default:
		return nil, fmt.Errorf("cannot convert non-NIST *ecdh.PublicKey to *ecdsa.PublicKey")
	}
}

func Test_ecdhPublicKeyToECDSA(t *testing.T) {
	tests := [...]struct {
		name  string
		curve elliptic.Curve
	}{
		// P224 not supported by ecdh
		{
			name:  "P256",
			curve: elliptic.P256(),
		},
		{
			name:  "P256",
			curve: elliptic.P384(),
		},
		{
			name:  "P521",
			curve: elliptic.P521(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("generating ecdsa.PrivateKey: %s", err)
			}
			original := &pk.PublicKey
			converted, err := original.ECDH()
			if err != nil {
				t.Fatalf("converting ecdsa.PublicKey to ecdh.PublicKey: %s", err)
			}
			roundtrip, err := ecdhPublicKeyToECDSA(converted)
			if err != nil {
				t.Fatalf("converting ecdh.PublicKey back to ecdsa.PublicKey: %s", err)
			}
			if !roundtrip.Equal(original) {
				t.Errorf("Roundtrip changed key from %v to %v", original, roundtrip)
			}
		})
	}
}

func parseVapidAuthHeader(authHeader string, applicationServerKey *ecdsa.PublicKey) (*jwt.Token, error) {
	if authHeader == "" {
		return nil, fmt.Errorf("missing auth header")
	}
	// the Authorization header should be of the form "vapid t=JWT, k=key" (RFC8292)
	// we need to extract the JWT (JSON Web Token) from t to check the signature using k
	authBody, found := strings.CutPrefix(authHeader, "vapid ")
	if !found {
		return nil, fmt.Errorf("Authorization header is not vapid: %s", authHeader)
	}
	authFields := strings.Split(authBody, ",")
	rawJWT := ""
	rawKey := ""
	for _, field := range authFields {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) < 2 {
			return nil, fmt.Errorf("push service vapid Authorization header field %q malformed", field)
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		switch key {
		case "t":
			rawJWT = val
		case "k":
			rawKey = val
		default:
			// other fields irrelevant to us
		}
	}
	if rawJWT == "" {
		return nil, fmt.Errorf("vapid Authorization header lacks \"t\" field (JWT)")
	}
	if rawKey == "" {
		return nil, fmt.Errorf("vapid Authorization header lacks \"k\" field")
	}
	key, err := decodeVAPIDPublicKey(rawKey)
	if err != nil {
		return nil, fmt.Errorf("parsing vapid Authorization key: %w", err)
	}
	// check that the key matches the known applicationServerKey
	// (RFC8292 4.2)
	if !key.Equal(applicationServerKey) {
		// in real code, this would mean the user agent needs to resubscribe with the new applicationServerKey
		return nil, fmt.Errorf("vapid Authorization key does not match applicationServerKey from subscription")
	}

	// verify the JWT signature
	token, err := parseJWT(rawJWT, key)
	if err != nil {
		return nil, fmt.Errorf("parsing vapid Authorization JWT: %w", err)
	}
	return token, nil
}

func parseJWT(rawJWT string, applicationServerKey *ecdsa.PublicKey) (*jwt.Token, error) {
	token, err := jwt.Parse(rawJWT, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.Alg() {
		case "ES256":
			return applicationServerKey, nil
		default:
			return nil, fmt.Errorf("unsupported JWT signing alg %q", t.Method.Alg())
		}
	})
	if err != nil {
		return nil, fmt.Errorf("decoding JWT %s: %w", rawJWT, err)
	}
	return token, nil
}

func decodeNotification(body []byte, authSecret [16]byte, userAgentKey *ecdsa.PrivateKey) (string, error) {
	// remember initial body length, before we start consuming it
	bodyLen := len(body)
	// the body is aes128gcm-encoded as described in RFC8188,
	// starting with this header:
	// +-----------+--------+-----------+---------------+
	// | salt (16) | rs (4) | idlen (1) | keyid (idlen) |
	// +-----------+--------+-----------+---------------+
	salt, body := body[:16], body[16:]
	recordSize, body := int(binary.BigEndian.Uint32(body[:4])), body[4:]
	idLen, body := int(uint8(body[0])), body[1:]
	rawPubKey, body := body[:idLen], body[idLen:]
	if bodyLen != recordSize {
		// this could mean a multi-record message was sent, this simplified parser does not support those.
		return "", fmt.Errorf("expected body length %d, got %d", recordSize, bodyLen)
	}

	// parse keys and derive shared secret
	pubKey, err := decodeECDSAPublicKey(rawPubKey)
	if err != nil {
		return "", fmt.Errorf("decoding public key from header: %w", err)
	}
	pubKeyECDH, err := pubKey.ECDH()
	if err != nil {
		return "", fmt.Errorf("converting public key to ECDH: %w", err)
	}
	userAgentECDHKey, err := userAgentKey.ECDH()
	if err != nil {
		return "", fmt.Errorf("converting user agent private key to ECDH: %w", err)
	}
	userAgentECDHPublicKey, err := userAgentKey.PublicKey.ECDH()
	if err != nil {
		return "", fmt.Errorf("converting user agent public key to ECDH: %w", err)
	}

	sharedECDHSecret, err := userAgentECDHKey.ECDH(pubKeyECDH)
	if err != nil {
		return "", fmt.Errorf("deriving shared secret from notification public key and user agent private key: %w", err)
	}

	hash := sha256.New

	// ikm
	prkInfoBuf := bytes.NewBuffer([]byte("WebPush: info\x00"))
	prkInfoBuf.Write(userAgentECDHPublicKey.Bytes()) // aka "dh"
	prkInfoBuf.Write(pubKeyECDH.Bytes())

	prkHKDF := hkdf.New(hash, sharedECDHSecret, authSecret[:], prkInfoBuf.Bytes())
	ikm, err := getHKDFKey(prkHKDF, 32)
	if err != nil {
		return "", fmt.Errorf("deriving ikm: %w", err)
	}

	// Derive Content Encryption Key
	contentEncryptionKeyInfo := []byte("Content-Encoding: aes128gcm\x00")
	contentHKDF := hkdf.New(hash, ikm, salt, contentEncryptionKeyInfo)
	contentEncryptionKey, err := getHKDFKey(contentHKDF, 16)
	if err != nil {
		return "", fmt.Errorf("deriving content encryption key: %w", err)
	}

	// Derive the Nonce
	nonceInfo := []byte("Content-Encoding: nonce\x00")
	nonceHKDF := hkdf.New(hash, ikm, salt, nonceInfo)
	nonce, err := getHKDFKey(nonceHKDF, 12)
	if err != nil {
		return "", fmt.Errorf("deriving nonce: %w", err)
	}

	// Cipher
	c, err := aes.NewCipher(contentEncryptionKey)
	if err != nil {
		return "", fmt.Errorf("creating cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	// Decrypt
	res, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return "", fmt.Errorf("decrypting: %w", err)
	}

	// the message is padded with 0x02 0x00 0x00 0x00 [...] 0x00, we need to remove that
	lastNull := len(res)
	for ; lastNull > 0 && res[lastNull-1] == 0x00; lastNull-- {
	}
	if lastNull == 0 {
		// we expect at least one 0x02 (or 0x01) before the nulls, not finding one is wrong
		return "", fmt.Errorf("decryption yielded only %d null bytes", len(res))
	}
	if beforeNull := res[lastNull-1]; beforeNull != 0x02 {
		// if we get an 0x01, it means we have a multi-record message, this mock does not implement those
		return "", fmt.Errorf("padding nulls in decrypted message should be preceded by 0x02 delimiter, got %02X", beforeNull)
	}
	// strip trailing nulls and separating 0x02
	res = res[:lastNull-1]

	return string(res), nil
}

// test for the decoding helper function
func Test_decodeVAPIDPublicKey(t *testing.T) {
	privKeyB64, pubKeyB64, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatalf("generating VAPID keys: %s", err)
	}

	// as a baseline, decode using the library functions
	privKeyBytes, err := decodeVapidKey(privKeyB64)
	if err != nil {
		t.Fatalf("decoding private key: %s", err)
	}
	privKey := generateVAPIDHeaderKeys(privKeyBytes)
	wantPubKey := &privKey.PublicKey

	// now decode using our test helper and compare the results
	gotPubKey, err := decodeVAPIDPublicKey(pubKeyB64)
	if err != nil {
		t.Fatalf("decoding public key")
	}
	if !gotPubKey.Equal(wantPubKey) {
		t.Errorf("result differs:\ngot:  %v\nwant: %v", gotPubKey, wantPubKey)
	}
}
