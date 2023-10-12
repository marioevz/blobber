package config_test

import (
	"fmt"
	"testing"

	"github.com/marioevz/blobber/config"
)

func TestKeysFromFile(t *testing.T) {
	testFile := "keys_test.txt"
	vk, err := config.KeyListFromFile(testFile)
	if err != nil {
		t.Fatalf("failed to read keys from file: %s", err)
	}
	if len(vk) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(vk))
	}

	expectedPubKeys := []string{
		"a9c279d3b5f270331d77b106b1870963f2a161184c09f00167677e5cefcec564dbb794424bca495e7aae893813ae3527",
		"b14d36b47e754d0be10dc715f8b13c1110b87ac6623f8c3602bde873390d81fdbc23c88d0e6a15aabf73f169be0f20d1",
	}

	for i, key := range vk {
		if fmt.Sprintf("%x", key.ValidatorPubkey) != expectedPubKeys[i] {
			t.Fatalf("expected pubkey %s, got %s", expectedPubKeys[i], fmt.Sprintf("%x", key.ValidatorPubkey))
		}
	}
}
