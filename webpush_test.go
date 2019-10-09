package webpush

import (
	"net/http"
	"strings"
	"testing"
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
	resp, err := SendNotification([]byte("Test"), getURLEncodedTestSubscription(), &Options{
		HTTPClient:      &testHTTPClient{},
		RecordSize:      3070,
		Subscriber:      "<EMAIL@EXAMPLE.COM>",
		Topic:           "test_topic",
		TTL:             0,
		Urgency:         "low",
		VAPIDPublicKey:  "test-public",
		VAPIDPrivateKey: "test-private",
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf(
			"Incorreect status code, expected=%d, got=%d",
			resp.StatusCode,
			201,
		)
	}
}

func TestSendNotificationToStandardEncodedSubscription(t *testing.T) {
	resp, err := SendNotification([]byte("Test"), getStandardEncodedTestSubscription(), &Options{
		HTTPClient:      &testHTTPClient{},
		Subscriber:      "<EMAIL@EXAMPLE.COM>",
		Topic:           "test_topic",
		TTL:             0,
		Urgency:         "low",
		VAPIDPrivateKey: "testKey",
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf(
			"Incorreect status code, expected=%d, got=%d",
			resp.StatusCode,
			201,
		)
	}
}

func TestSendTooLargeNotification(t *testing.T) {
	_, err := SendNotification([]byte(strings.Repeat("Test", int(MaxRecordSize))), getStandardEncodedTestSubscription(), &Options{
		HTTPClient:      &testHTTPClient{},
		Subscriber:      "<EMAIL@EXAMPLE.COM>",
		Topic:           "test_topic",
		TTL:             0,
		Urgency:         "low",
		VAPIDPrivateKey: "testKey",
	})
	if err == nil {
		t.Fatal("Expected error with too large payload")
	}
}
