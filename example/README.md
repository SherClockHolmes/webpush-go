# example

## Access index.html

Replace the public VAPID key in index.html.

Use a tool such as SimpleHTTPServer to run a web server:

```bash
python3 -m http.server 8000
```

Go to `http://localhost:8000` and copy the logged subsciption from the console.

## Test send a notification

Replace the public/private VAPID keys. Use the subscription you had from the first section.

```bash
go run main.go
```
