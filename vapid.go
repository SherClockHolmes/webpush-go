package webpush

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// GenerateVAPIDKeys will create a private and public VAPID key pair
func GenerateVAPIDKeys() (privateKey, publicKey string, err error) {
	// Get the private key from the P256 curve
	curve := elliptic.P256()

	private, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return
	}

	public := elliptic.Marshal(curve, x, y)

	// Convert to base64
	publicKey = base64.RawURLEncoding.EncodeToString(public)
	privateKey = base64.RawURLEncoding.EncodeToString(private)

	return
}

// Generates the ECDSA public and private keys for the JWT encryption
func generateVAPIDHeaderKeys(privateKey []byte) (*ecdsa.PublicKey, *ecdsa.PrivateKey) {
	// Public key
	curve := elliptic.P256()
	px, py := curve.ScalarMult(
		curve.Params().Gx,
		curve.Params().Gy,
		privateKey,
	)

	pubKey := ecdsa.PublicKey{
		Curve: curve,
		X:     px,
		Y:     py,
	}

	// Private key
	d := &big.Int{}
	d.SetBytes(privateKey)

	return &pubKey, &ecdsa.PrivateKey{
		PublicKey: pubKey,
		D:         d,
	}
}

// Sign the http.Request with the required VAPID headers
func vapid(req *http.Request, s *Subscription, options *Options) error {
	// Create the JWT token
	subURL, err := url.Parse(s.Endpoint)
	if err != nil {
		return err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"aud": fmt.Sprintf("%s://%s", subURL.Scheme, subURL.Host),
		"exp": time.Now().Add(time.Hour * 12).Unix(),
		"sub": options.Subscriber,
	})

	// ECDSA
	b64 := base64.RawURLEncoding
	decodedVapidPrivateKey, err := b64.DecodeString(options.VAPIDPrivateKey)
	if err != nil {
		return err
	}

	pubKey, privKey := generateVAPIDHeaderKeys(decodedVapidPrivateKey)

	// Sign token with key
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return err
	}

	// Set VAPID headers
	req.Header.Set("Authorization", fmt.Sprintf("WebPush %s", tokenString))

	vapidPublicKeyHeader := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	req.Header.Set(
		"Crypto-key",
		fmt.Sprintf(
			"%s;p256ecdsa=%s",
			req.Header.Get("Crypto-Key"),
			base64.RawURLEncoding.EncodeToString(vapidPublicKeyHeader),
		),
	)

	return nil
}
