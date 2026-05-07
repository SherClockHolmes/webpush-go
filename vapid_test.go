package webpush

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVAPID(t *testing.T) {
	s := getStandardEncodedTestSubscription()
	sub := "test@test.com"

	// Generate vapid keys
	vapidPrivateKey, vapidPublicKey, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	// Unusual expiration to check that the expiration value is used
	expiration := time.Now().Add(time.Hour * 11).Add(23 * time.Minute)

	tests := []struct {
		authScheme AuthScheme
	}{
		{Vapid},
		{WebPush},
	}

	for _, test := range tests {
		// Get authentication header
		vapidHeaders, err := generateVAPIDHeaders(
			s.Endpoint,
			sub,
			vapidPublicKey,
			vapidPrivateKey,
			expiration,
			test.authScheme,
		)
		if err != nil {
			t.Fatal(err)
		}

		// Validate the token in the Authorization header
		tokenString := getTokenFromAuthorizationHeader(vapidHeaders["Authorization"], test.authScheme, t)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				t.Fatal("Wrong validation method need ECDSA!")
			}

			// To decode the token it needs the VAPID public key
			b64 := base64.RawURLEncoding
			decodedVapidPrivateKey, err := b64.DecodeString(vapidPrivateKey)
			if err != nil {
				t.Fatal("Could not decode VAPID private key")
			}

			privKey := generateVAPIDHeaderKeys(decodedVapidPrivateKey)
			return privKey.Public(), nil
		})

		// Check the claims on the token
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			expectedSub := fmt.Sprintf("mailto:%s", sub)
			if expectedSub != claims["sub"] {
				t.Fatalf(
					"Incorreect mailto, expected=%s, got=%s",
					expectedSub,
					claims["sub"],
				)
			}

			if claims["aud"] == "" {
				t.Fatal("Audience should not be empty")
			}

			expectedExp := float64(expiration.Unix())
			if expectedExp != claims["exp"] {
				t.Fatalf(
					"Incorrect exp, expected=%v, got=%v",
					expectedExp,
					claims["exp"],
				)
			}
		} else {
			t.Fatal(err)
		}

		// Check headers
		switch test.authScheme {
		case WebPush:
			if vapidHeaders["Crypto-Key"] != "p256ecdsa="+vapidPublicKey {
				t.Fatalf("Incorrect crypto key header, expected=%s, got=%s", "p256ecdsa="+vapidPublicKey, vapidHeaders["Crypto-Key"])
			}
		case Vapid:
			pubKey, err := decodeVapidKey(vapidPublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(vapidHeaders["Authorization"], "k="+base64.RawURLEncoding.EncodeToString(pubKey)) {
				t.Fatalf("Incorrect authorization header, expected to contain k=%s, got=%s", vapidPublicKey, vapidHeaders["Authorization"])
			}
		}
	}
}

func TestVAPIDSubscriberFormats(t *testing.T) {
	s := getStandardEncodedTestSubscription()
	vapidPrivateKey, vapidPublicKey, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"bare email", "test@test.com", "mailto:test@test.com"},
		{"mailto URI", "mailto:test@test.com", "mailto:test@test.com"},
		{"https URI", "https://example.com/contact", "https://example.com/contact"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vapidHeaders, err := generateVAPIDHeaders(
				s.Endpoint,
				tt.input,
				vapidPublicKey,
				vapidPrivateKey,
				time.Now().Add(time.Hour),
				Vapid,
			)
			if err != nil {
				t.Fatal(err)
			}

			tokenString := getTokenFromAuthorizationHeader(vapidHeaders["Authorization"], Vapid, t)
			token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				b64 := base64.RawURLEncoding
				decodedVapidPrivateKey, err := b64.DecodeString(vapidPrivateKey)
				if err != nil {
					return nil, err
				}
				return generateVAPIDHeaderKeys(decodedVapidPrivateKey).Public(), nil
			})

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok || !token.Valid {
				t.Fatal("invalid token")
			}
			if claims["sub"] != tt.expected {
				t.Fatalf("sub: expected=%q got=%q", tt.expected, claims["sub"])
			}
		})
	}
}

func TestVAPIDKeys(t *testing.T) {
	privateKey, publicKey, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	if len(privateKey) != 43 {
		t.Fatal("Generated incorrect VAPID private key")
	}

	if len(publicKey) != 87 {
		t.Fatal("Generated incorrect VAPID public key")
	}
}

// Helper function for extracting the token from the Authorization header
func getTokenFromAuthorizationHeader(tokenHeader string, authScheme AuthScheme, t *testing.T) string {
	switch authScheme {
	case WebPush:
		hsplit := strings.Split(tokenHeader, " ")
		if len(hsplit) != 2 {
			t.Fatalf("Failed to auth split header, expected 2 parts, got %d", len(hsplit))
		}

		if hsplit[0] != "WebPush" {
			t.Fatalf("Incorrect scheme, expected WebPush, got %s", hsplit[0])
		}

		return hsplit[1]
	default: // Vapid
		hsplit := strings.Split(tokenHeader, " ")
		if len(hsplit) < 3 {
			t.Fatal("Failed to auth split header")
		}

		tsplit := strings.Split(hsplit[1], "=")
		if len(tsplit) < 2 {
			t.Fatal("Failed to t split header on =")
		}

		return tsplit[1][:len(tsplit[1])-1]
	}
}
