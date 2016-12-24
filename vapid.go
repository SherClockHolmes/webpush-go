package webpush

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// Sign the http.Request with the required VAPID headers
func vapid(s *Subscription, req *http.Request, options *Options) error {
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

	// ecdsa key
	b64 := base64.RawURLEncoding
	signVapidPrivateKey, err := b64.DecodeString(options.VapidPrivateKey)
	if err != nil {
		return err
	}

	curve := elliptic.P256()
	px, py := curve.ScalarMult(curve.Params().Gx, curve.Params().Gy, signVapidPrivateKey)
	pubKey := ecdsa.PublicKey{Curve: curve, X: px, Y: py}
	d := &big.Int{}
	d.SetBytes(signVapidPrivateKey)
	privKey := ecdsa.PrivateKey{PublicKey: pubKey, D: d}

	// Sign token with key
	tokenString, err := token.SignedString(&privKey)
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
