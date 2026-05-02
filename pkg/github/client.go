/*
Copyright 2026 The BlanketOps Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://api.github.com"
	defaultTimeout = 30 * time.Second
)

// Client is a minimal GitHub API client scoped to webhook management.
// It uses the GitHub REST API v3 with a personal access token or
// GitHub App installation token.
type Client struct {
	token      string
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a GitHub client authenticated with the given token.
func NewClient(token string) *Client {
	return &Client{
		token:   token,
		baseURL: defaultBaseURL,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// webhookConfig is the GitHub API payload for creating/updating a webhook.
type webhookConfig struct {
	URL         string `json:"url"`
	ContentType string `json:"content_type"`
	Secret      string `json:"secret,omitempty"`
	InsecureSSL string `json:"insecure_ssl"`
}

type createWebhookRequest struct {
	Name   string        `json:"name"`
	Active bool          `json:"active"`
	Events []string      `json:"events"`
	Config webhookConfig `json:"config"`
}

type updateWebhookRequest struct {
	Active bool          `json:"active"`
	Events []string      `json:"events"`
	Config webhookConfig `json:"config"`
}

type webhookResponse struct {
	ID int64 `json:"id"`
}

// CreateWebhook registers a new webhook on a GitHub repository.
// Returns the GitHub-assigned webhook ID.
func (c *Client) CreateWebhook(
	ctx context.Context,
	repository string,
	hookURL string,
	events []string,
	secret string,
	insecureSSL bool,
	contentType string,
) (int64, error) {
	if contentType == "" {
		contentType = "json"
	}
	if len(events) == 0 {
		events = []string{"push"}
	}

	insecureSSLStr := "0"
	if insecureSSL {
		insecureSSLStr = "1"
	}

	payload := createWebhookRequest{
		Name:   "web",
		Active: true,
		Events: events,
		Config: webhookConfig{
			URL:         hookURL,
			ContentType: contentType,
			Secret:      secret,
			InsecureSSL: insecureSSLStr,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	url := fmt.Sprintf("%s/repos/%s/hooks", c.baseURL, repository)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to call GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return 0, fmt.Errorf("GitHub API returned %d for CreateWebhook on %s", resp.StatusCode, repository)
	}

	var result webhookResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode webhook response: %w", err)
	}

	return result.ID, nil
}

// UpdateWebhook updates an existing webhook on a GitHub repository.
func (c *Client) UpdateWebhook(
	ctx context.Context,
	repository string,
	webhookID int64,
	hookURL string,
	events []string,
	secret string,
	insecureSSL bool,
	contentType string,
) error {
	if contentType == "" {
		contentType = "json"
	}
	if len(events) == 0 {
		events = []string{"push"}
	}

	insecureSSLStr := "0"
	if insecureSSL {
		insecureSSLStr = "1"
	}

	payload := updateWebhookRequest{
		Active: true,
		Events: events,
		Config: webhookConfig{
			URL:         hookURL,
			ContentType: contentType,
			Secret:      secret,
			InsecureSSL: insecureSSLStr,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	url := fmt.Sprintf("%s/repos/%s/hooks/%d", c.baseURL, repository, webhookID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API returned %d for UpdateWebhook %d on %s",
			resp.StatusCode, webhookID, repository)
	}

	return nil
}

// DeleteWebhook removes a webhook from a GitHub repository.
// Returns nil if the webhook is already gone (404).
func (c *Client) DeleteWebhook(
	ctx context.Context,
	repository string,
	webhookID int64,
) error {
	url := fmt.Sprintf("%s/repos/%s/hooks/%d", c.baseURL, repository, webhookID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call GitHub API: %w", err)
	}
	defer resp.Body.Close()

	// 204 = deleted, 404 = already gone — both are fine
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("GitHub API returned %d for DeleteWebhook %d on %s",
			resp.StatusCode, webhookID, repository)
	}

	return nil
}

// WebhookExists checks whether a webhook with the given ID exists on the repository.
func (c *Client) WebhookExists(
	ctx context.Context,
	repository string,
	webhookID int64,
) (bool, error) {
	url := fmt.Sprintf("%s/repos/%s/hooks/%d", c.baseURL, repository, webhookID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to call GitHub API: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("GitHub API returned %d for WebhookExists %d on %s",
			resp.StatusCode, webhookID, repository)
	}
}

// setHeaders applies required headers to every GitHub API request.
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.token))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}
