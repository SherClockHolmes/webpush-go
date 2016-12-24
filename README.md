# webpush-go

Web Push API Encryption with VAPID support.

## Dependencies

1. Install [Go 1.7](https://golang.org/) ([gvm](https://github.com/moovweb/gvm) recommended)
2. Get [gvt](https://github.com/FiloSottile/gvt) `go get -u github.com/FiloSottile/gvt`
3. `gvt restore`

## Example

```golang
package main

import (
	"bytes"
	"encoding/json"
	"log"

	webpush "github.com/sherclockholmes/webpush-go"
)

const (
	vapidPrivateKey = "<YOUR VAPID PRIVATE KEY>"
)

func main() {
	subJSON := `{<YOUR SUBSCRIPTION JSON>}`

	// Decode subscription
	s := webpush.Subscription{}
	if err := json.NewDecoder(bytes.NewBufferString(subJSON)).Decode(&s); err != nil {
		log.Fatal(err)
	}

	// Send Notification
	_, err = webpush.SendNotification(&s, []byte("Test"), &webpush.Options{
		Subscriber:      "mailto:<EMAIL@EXAMPLE.COM>",
		TTL:             60,
		VapidPrivateKey: vapidPrivateKey,
	})
	if err != nil {
		log.Fatal(err)
	}
}
```

### Similar Projects / Inspired By

- [Push Encryption (Go)](https://github.com/GoogleChrome/push-encryption-go)  
- [go-ecdh](https://github.com/wsddn/go-ecdh)  
- [WebPush Libs](https://github.com/web-push-libs)  
- [WebPush Test Page](https://jrconlin.github.io/WebPushDataTestPage/)


### References

For more information visit these [Google Developers](https://developers.google.com/web) links:

[https://developers.google.com/web/updates/2016/03/web-push-encryption](https://developers.google.com/web/updates/2016/03/web-push-encryption)  
[https://developers.google.com/web/updates/2016/07/web-push-interop-wins](https://developers.google.com/web/updates/2016/03/web-push-encryption)
