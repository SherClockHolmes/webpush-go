package webpush

// urgency indicates to the push service how important a message is to the user.
// This can be used by the push service to help conserve the battery life of a user's device
// by only waking up for important messages when battery is low.
type urgency string

const (
	// UrgencyVeryLow requires device state: on power and Wi-Fi
	UrgencyVeryLow urgency = "very-low"
	// UrgencyLow requires device state: on either power or Wi-Fi
	UrgencyLow urgency = "low"
	// UrgencyNormal excludes device state: low battery
	UrgencyNormal urgency = "normal"
	// UrgencyHigh admits device state: low battery
	UrgencyHigh urgency = "high"
)
