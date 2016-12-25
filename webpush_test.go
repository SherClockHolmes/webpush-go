package webpush

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testHTTPClient struct{}

func (*testHTTPClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200}, nil
}

func getTestSubscription() *Subscription {
	return &Subscription{
		Endpoint: "https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		Keys: Keys{
			P256dh: "BNNL5ZaTfK81qhXOx23-wewhigUeFb632jN6LvRWCFH1ubQr77FE_9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk",
			Auth:   "zqbxT6JKstKSY9JKibZLSQ",
		},
	}
}

func TestSendNotification(t *testing.T) {
	assert := assert.New(t)

	resp, err := SendNotification([]byte("Test"), getTestSubscription(), &Options{
		HTTPClient:      &testHTTPClient{},
		Subscriber:      "mailto:<EMAIL@EXAMPLE.COM>",
		TTL:             0,
		VAPIDPrivateKey: "testKey",
	})

	assert.Equal(200, resp.StatusCode)
	assert.Nil(err)
}
