# webpush-go

[![Go Report Card](https://goreportcard.com/badge/github.com/SherClockHolmes/webpush-go)](https://goreportcard.com/report/github.com/SherClockHolmes/webpush-go)
[![GoDoc](https://godoc.org/github.com/SherClockHolmes/webpush-go?status.svg)](https://godoc.org/github.com/SherClockHolmes/webpush-go)

Web Push API Encryption with VAPID support.

```bash
go get -u github.com/SherClockHolmes/webpush-go
```

## Example

For a full example, refer to the code in the [example](example/) directory.

```go
package main

import (
	"encoding/json"

	webpush "github.com/SherClockHolmes/webpush-go"
)

func main() {
	// Decode subscription
	s := &webpush.Subscription{}
	json.Unmarshal([]byte("<YOUR_SUBSCRIPTION>"), s)

	// Send Notification
	resp, err := webpush.SendNotification([]byte("Test"), s, &webpush.Options{
		Subscriber:      "example@example.com",
		VAPIDPublicKey:  "<YOUR_VAPID_PUBLIC_KEY>",
		VAPIDPrivateKey: "<YOUR_VAPID_PRIVATE_KEY>",
		TTL:             30,
	})
	if err != nil {
		// TODO: Handle error
	}
	defer resp.Body.Close()
}
```

### Auth Scheme

If you need to support the legacy authentication scheme, for example for retro-compatibility with a browser from 2016, you can specify the VAPID authentication scheme to use.
Note that using the legacy scheme may break push notifications on recent applications.

*   `vapid`: The standard and recommended scheme, used by Firefox, Chrome and all browsers.
*   `webpush`: The legacy scheme, from a [draft of webpush deprecated in 2016](https://datatracker.ietf.org/doc/draft-ietf-webpush-vapid/01/).

You can specify the scheme in the `Options` struct:

```go
&webpush.Options{
    AuthScheme: webpush.WebPush,
    // ... other options
}
```

If no `AuthScheme` is specified, it will default to `vapid`.

### Generating VAPID Keys

Use the helper method `GenerateVAPIDKeys` to generate the VAPID key pair.

```golang
privateKey, publicKey, err := webpush.GenerateVAPIDKeys()
if err != nil {
	// TODO: Handle error
}
```

## Development

1. Install [Go 1.11+](https://golang.org/)
2. `go mod vendor`
3. `go test`

#### For other language implementations visit:

[WebPush Libs](https://github.com/web-push-libs)
