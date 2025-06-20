package beacon

import (
	"fmt"
	"net/url"
	"strings"
)

// ParseBeaconURL parses a beacon client URL and returns the HTTP endpoint
func ParseBeaconURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("empty URL")
	}
	
	// Handle the case where no scheme is provided
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	// Ensure we have a valid scheme
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid scheme: %s", u.Scheme)
	}

	// Return the full URL string including all components
	return u.String(), nil
}