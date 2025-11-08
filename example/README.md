# Example

This example demonstrates how to use the `webpush-go` library to send push notifications.

## Running the Example

1.  **Start the server:**

    ```bash
    go run main.go
    ```

    The server will start on port 8080 and generate the VAPID keys.

2.  **Subscribe to notifications:**

    Open your browser and navigate to `http://localhost:8080`. The browser will ask for permission to show notifications. Click "Allow".

3.  **Send a test notification:**

    Click the "Send Test Notification" button. You should receive a push notification in your browser.

## How it Works

*   The `main.go` file starts a web server that serves the `index.html` and `service-worker.js` files.
*   When you visit `index.html`, the JavaScript code subscribes to push notifications and sends the subscription object to the server.
*   The server stores the subscription in memory.
*   When you click the "Send Test Notification" button, the browser sends a request to the server, which then uses the `webpush-go` library to send a notification to your browser.

### Browser Compatibility

The example has crude browser detection and sends the appropriate VAPID authentication scheme to the server.

*   For Chrome, it uses the `webpush` scheme.
*   For other browsers, it uses the `vapid` scheme.

This is handled in the `index.html` file, where the browser is detected and the `authScheme` is sent to the server when a notification is requested. The `main.go` server then uses this `authScheme` to send the notification with the correct VAPID headers.
