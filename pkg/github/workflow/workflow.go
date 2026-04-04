// pkg/github/workflow/workflow.go
package workflow

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/google/go-github/v71/github"
	"golang.org/x/oauth2"
)

const blanketopsWorkflow = `name: BlanketOps Supply Chain
on:
  push:
    branches: ["*"]
  pull_request:
    branches: ["*"]

permissions:
  id-token: write
  contents: read

jobs:
  notify:
    runs-on: ubuntu-latest
    steps:
      - name: Get OIDC Token
        id: oidc
        run: |
          TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sigstore" | jq -r '.value')
          echo "token=$TOKEN" >> $GITHUB_OUTPUT

      - name: Notify BlanketOps
        run: |
          curl -X POST ${{ secrets.BLANKETOPS_LISTENER_URL }} \
            -H "Content-Type: application/json" \
            -d '{
              "repository": "${{ github.repository }}",
              "ref": "${{ github.ref }}",
              "sha": "${{ github.sha }}",
              "oidc_token": "${{ steps.oidc.outputs.token }}"
            }'
`

type Client struct {
	gh *github.Client
}

func NewClient(ctx context.Context, token string) *Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	return &Client{gh: github.NewClient(tc)}
}

func (c *Client) Inject(
	ctx context.Context,
	owner, repo, path string,
) error {
	content := []byte(blanketopsWorkflow)
	encoded := base64.StdEncoding.EncodeToString(content)

	// Check if file already exists
	existing, _, _, err := c.gh.Repositories.GetContents(
		ctx, owner, repo, path, nil,
	)

	if err == nil && existing != nil {
		// Update existing file
		_, _, err = c.gh.Repositories.UpdateFile(ctx, owner, repo, path, &github.RepositoryContentFileOptions{
			Message: github.Ptr("chore: update BlanketOps supply chain workflow"),
			Content: []byte(encoded),
			SHA:     existing.SHA,
		})
		return err
	}

	// Create new file
	_, _, err = c.gh.Repositories.CreateFile(ctx, owner, repo, path, &github.RepositoryContentFileOptions{
		Message: github.Ptr("chore: inject BlanketOps supply chain workflow"),
		Content: []byte(encoded),
	})
	if err != nil {
		return fmt.Errorf("injecting workflow: %w", err)
	}

	return nil
}

func (c *Client) RegisterSecret(
	ctx context.Context,
	owner, repo, secretName, secretValue string,
) error {
	// Get repo public key for secret encryption
	key, _, err := c.gh.Actions.GetRepoPublicKey(ctx, owner, repo)
	if err != nil {
		return fmt.Errorf("getting repo public key: %w", err)
	}

	// Encrypt the secret value
	encrypted, err := encryptSecret(key, secretValue)
	if err != nil {
		return fmt.Errorf("encrypting secret: %w", err)
	}

	_, err = c.gh.Actions.CreateOrUpdateRepoSecret(ctx, owner, repo, &github.EncryptedSecret{
		Name:           secretName,
		KeyID:          key.GetKeyID(),
		EncryptedValue: encrypted,
	})
	if err != nil {
		return fmt.Errorf("registering repo secret: %w", err)
	}

	return nil
}