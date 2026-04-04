// pkg/github/workflow/encrypt.go
package workflow

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/google/go-github/v71/github"
	"golang.org/x/crypto/nacl/box"
)

func encryptSecret(key *github.PublicKey, value string) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(key.GetKey())
	if err != nil {
		return "", fmt.Errorf("decoding public key: %w", err)
	}

	var recipientKey [32]byte
	copy(recipientKey[:], keyBytes)

	encrypted, err := box.SealAnonymous(nil, []byte(value), &recipientKey, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("encrypting: %w", err)
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}
