# webpush-go

[![Go Report Card](https://goreportcard.com/badge/github.com/SherClockHolmes/webpush-go)](https://goreportcard.com/report/github.com/SherClockHolmes/webpush-go)
[![GoDoc](https://godoc.org/github.com/SherClockHolmes/webpush-go?status.svg)](https://godoc.org/github.com/SherClockHolmes/webpush-go)

Web Push API Encryption with VAPID support.

```bash
go get -u github.com/SherClockHolmes/webpush-go
```

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
	_, err := webpush.SendNotification([]byte("Test"), &s, &webpush.Options{
		Subscriber:      "<EMAIL@EXAMPLE.COM>",
		TTL:             60,
		VAPIDPrivateKey: vapidPrivateKey,
	})
	if err != nil {
		log.Fatal(err)
	}
}
```

### Generating VAPID Keys

Use the helper method `GenerateVAPIDKeys` to generate the VAPID key pair.

```golang
privateKey, publicKey, err := webpush.GenerateVAPIDKeys()
if err != nil {
    // TODO: Handle failure!
}
```

## Dependencies

1. Install [Go 1.8+](https://golang.org/) ([gvm](https://github.com/moovweb/gvm) recommended)
2. Get [gvt](https://github.com/FiloSottile/gvt) `go get -u github.com/FiloSottile/gvt`
3. `gvt restore`

## References

For more information visit these [Google Developers](https://developers.google.com/web) links:

[https://developers.google.com/web/updates/2016/03/web-push-encryption](https://developers.google.com/web/updates/2016/03/web-push-encryption)  
[https://developers.google.com/web/updates/2016/07/web-push-interop-wins](https://developers.google.com/web/updates/2016/03/web-push-encryption)

### Similar Projects / Inspired By

- [Push Encryption (Go)](https://github.com/GoogleChrome/push-encryption-go)
- [go-ecdh](https://github.com/wsddn/go-ecdh)
- [WebPush Libs](https://github.com/web-push-libs)
- [Web Push: Data Encryption Test Page](https://jrconlin.github.io/WebPushDataTestPage/)
