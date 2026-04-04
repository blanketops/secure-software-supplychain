// pkg/github/webhook/webhook.go
package webhook

import (
	"context"
	"fmt"

	"github.com/google/go-github/v71/github"
	"golang.org/x/oauth2"
)

type Client struct {
	gh *github.Client
}

func NewClient(ctx context.Context, token string) *Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	return &Client{gh: github.NewClient(tc)}
}

func (c *Client) Register(
	ctx context.Context,
	owner, repo, listenerURL, secret string,
) (int64, error) {
	hook := &github.Hook{
		Name:   github.Ptr("web"),
		Active: github.Ptr(true),
		Events: []string{"push", "pull_request"},
		Config: &github.HookConfig{
			URL:         github.Ptr(listenerURL),
			ContentType: github.Ptr("json"),
			Secret:      github.Ptr(secret),
			InsecureSSL: github.Ptr("0"),
		},
	}

	created, _, err := c.gh.Repositories.CreateHook(ctx, owner, repo, hook)
	if err != nil {
		return 0, fmt.Errorf("registering webhook: %w", err)
	}

	return created.GetID(), nil
}

func (c *Client) Delete(
	ctx context.Context,
	owner, repo string,
	hookID int64,
) error {
	_, err := c.gh.Repositories.DeleteHook(ctx, owner, repo, hookID)
	if err != nil {
		return fmt.Errorf("deleting webhook: %w", err)
	}
	return nil
}

func (c *Client) Exists(
	ctx context.Context,
	owner, repo string,
	hookID int64,
) (bool, error) {
	_, _, err := c.gh.Repositories.GetHook(ctx, owner, repo, hookID)
	if err != nil {
		return false, nil
	}
	return true, nil
}