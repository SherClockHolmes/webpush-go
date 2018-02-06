package webpush

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testHTTPClient struct{}

func (*testHTTPClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 201}, nil
}

func getURLEncodedTestSubscription() *Subscription {
	return &Subscription{
		Endpoint: "https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		Keys: Keys{
			P256dh: "BNNL5ZaTfK81qhXOx23-wewhigUeFb632jN6LvRWCFH1ubQr77FE_9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk",
			Auth:   "zqbxT6JKstKSY9JKibZLSQ",
		},
	}
}

func getStandardEncodedTestSubscription() *Subscription {
	return &Subscription{
		Endpoint: "https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		Keys: Keys{
			P256dh: "BNNL5ZaTfK81qhXOx23+wewhigUeFb632jN6LvRWCFH1ubQr77FE/9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk=",
			Auth:   "zqbxT6JKstKSY9JKibZLSQ==",
		},
	}
}

func TestSendNotificationToURLEncodedSubscription(t *testing.T) {
	assert := assert.New(t)

	resp, err := SendNotification([]byte("Test"), getURLEncodedTestSubscription(), &Options{
		HTTPClient:      &testHTTPClient{},
		Subscriber:      "mailto:<EMAIL@EXAMPLE.COM>",
		Topic:           "test_topic",
		TTL:             0,
		Urgency:         "low",
		VAPIDPrivateKey: "testKey",
	})

	assert.Nil(err)
	assert.Equal(201, resp.StatusCode)
}

func TestSendNotificationToStandardEncodedSubscription(t *testing.T) {
	assert := assert.New(t)

	resp, err := SendNotification([]byte("Test"), getStandardEncodedTestSubscription(), &Options{
		HTTPClient:      &testHTTPClient{},
		Subscriber:      "mailto:<EMAIL@EXAMPLE.COM>",
		Topic:           "test_topic",
		TTL:             0,
		Urgency:         "low",
		VAPIDPrivateKey: "testKey",
	})

	assert.Nil(err)
	assert.Equal(201, resp.StatusCode)
}
