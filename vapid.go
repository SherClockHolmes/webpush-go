package webpush

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt"
)

// GenerateVAPIDKeys will create a private and public VAPID key pair
func GenerateVAPIDKeys() (privateKey, publicKey string, err error) {
	// Get the private key from the P256 curve
	curve := ecdh.P256()

	private, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return
	}

	// Convert to base64
	publicKey = base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	privateKey = base64.RawURLEncoding.EncodeToString(private.Bytes())
	return
}

// Generates the ECDSA public and private keys for the JWT encryption
func generateVAPIDHeaderKeys(privateKey []byte) (*ecdsa.PrivateKey, error) {
	key, err := ecdh.P256().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("validating private key: %w", err)
	}
	converted, err := ecdhPrivateKeyToECDSA(key)
	if err != nil {
		return nil, fmt.Errorf("converting private key to crypto/ecdsa: %w", err)
	}
	return converted, nil
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

func ecdhPrivateKeyToECDSA(key *ecdh.PrivateKey) (*ecdsa.PrivateKey, error) {
	// see https://github.com/golang/go/issues/63963
	pubKey, err := ecdhPublicKeyToECDSA(key.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("converting PublicKey part of *ecdh.PrivateKey: %w", err)
	}
	return &ecdsa.PrivateKey{
		PublicKey: *pubKey,
		D:         big.NewInt(0).SetBytes(key.Bytes()),
	}, nil
}

// getVAPIDAuthorizationHeader
func getVAPIDAuthorizationHeader(
	endpoint,
	subscriber,
	vapidPublicKey,
	vapidPrivateKey string,
	expiration time.Time,
) (string, error) {
	// Create the JWT token
	subURL, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"aud": fmt.Sprintf("%s://%s", subURL.Scheme, subURL.Host),
		"exp": expiration.Unix(),
		"sub": fmt.Sprintf("mailto:%s", subscriber),
	})

	// Decode the VAPID private key
	decodedVapidPrivateKey, err := decodeVapidKey(vapidPrivateKey)
	if err != nil {
		return "", err
	}

	privKey, err := generateVAPIDHeaderKeys(decodedVapidPrivateKey)
	if err != nil {
		return "", fmt.Errorf("generating VAPID header keys: %w", err)
	}

	// Sign token with private key
	jwtString, err := token.SignedString(privKey)
	if err != nil {
		return "", err
	}

	// Decode the VAPID public key
	pubKey, err := decodeVapidKey(vapidPublicKey)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(
		"vapid t=%s, k=%s",
		jwtString,
		base64.RawURLEncoding.EncodeToString(pubKey),
	), nil
}

// Need to decode the vapid private key in multiple base64 formats
// Solution from: https://github.com/SherClockHolmes/webpush-go/issues/29
func decodeVapidKey(key string) ([]byte, error) {
	bytes, err := base64.URLEncoding.DecodeString(key)
	if err == nil {
		return bytes, nil
	}

	return base64.RawURLEncoding.DecodeString(key)
}
