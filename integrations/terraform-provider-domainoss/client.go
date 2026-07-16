package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type client struct {
	endpoint string
	apiKey   string
	http     *http.Client
}

type apiEnvelope struct {
	Data json.RawMessage `json:"data"`
}

func newClient(endpoint, apiKey string) *client {
	return &client{
		endpoint: strings.TrimRight(endpoint, "/") + "/api/v1",
		apiKey:   apiKey,
		http:     &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *client) request(method, path string, input interface{}, output interface{}) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, c.endpoint+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Domain OSS API returned %d: %s", response.StatusCode, strings.TrimSpace(string(payload)))
	}
	if output != nil && len(payload) > 0 {
		return json.Unmarshal(payload, output)
	}
	return nil
}
