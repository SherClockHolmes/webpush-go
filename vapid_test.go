package webpush

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestVAPID(t *testing.T) {
	assert := assert.New(t)

	s := getTestSubscription()
	sub := "mailto:test@test.com"
	vapidPrivateKey := "MHcCAQEEIHF7ijDrb8gwj_9o7UuSx9t_oGlPMyOsG9YQLp3qJwLuoAoGCCqGSM49AwEHoUQDQgAEhB-nJdg0d5oOkdTYsKqbbuQ06ZUYkS0H-ELXsShIkpmcIVIO16Sj15YMBouesMbY4xPdepwF4Pj3QfaALRAG5Q"

	// Create the request
	req, err := http.NewRequest("POST", s.Endpoint, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Run the request through vapid()
	err = vapid(req, s, &Options{
		Subscriber:      sub,
		VAPIDPrivateKey: vapidPrivateKey,
	})

	assert.Nil(err)

	// Validate the token in the Authorization header
	tokenString := getTokenFromAuthorizationHeader(req.Header.Get("Authorization"), t)

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

		pubKey, _ := generateVAPIDHeaderKeys(decodedVapidPrivateKey)
		return pubKey, nil
	})

	// Check the claims on the token
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		assert.Equal(sub, claims["sub"])
		assert.NotEmpty(claims["aud"], "Audience should not be empty")
	} else {
		t.Fatal(err)
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
func getTokenFromAuthorizationHeader(tokenHeader string, t *testing.T) string {
	split := strings.Split(tokenHeader, " ")
	if len(split) < 2 {
		t.Fatal("Failed to split header")
	}

	switch split[0] {
	case "WebPush":
		fallthrough
	case "Bearer":
		return split[1]
	}

	t.Fatal("Something wrong happened")
	return ""
}
