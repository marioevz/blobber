package keys_test

import (
	"testing"

	"github.com/marioevz/blobber/keys"
)

func TestKeysFromFile(t *testing.T) {
	testFile := "keys_test.txt"
	vk, err := keys.KeyListFromFile(testFile)
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
		if key.PubKeyToHex() != expectedPubKeys[i] {
			t.Fatalf("expected pubkey %s, got %s", expectedPubKeys[i], key.PubKeyToHex())
		}
	}
}

func TestKeysFromFolder(t *testing.T) {
	expectedPublicKeys := []string{
		"811bced8ba35c8ef1b1688d8e7b7d083e2d2956aecfec95f934cef931831b471fa6d1cd443ede8f7569200b10458f21a", "96680a568ffc68ea8a0b478679f6cf1366a4984c3457fe9827b9d38028b23b0dbf36697c910f0802c82af2ece8dc8103", "b21aa7a4b2f7786f6d7d43b97e5745c6fad0072d2edf1fdee5130b5a5563f8fe1523b6e162071fe5d3cbdbbf32e36c31", "8bf5b521e92bba8e06c1a4c008d4c1ceff0123bddc06a5dd8b223064302740f00e3025f04d5eb64da9b428b1de9a1df4", "a0a0f2b4bb371986223a5457c68dcc1a217b537a4543fce4a614387629a67c70064d6507aee6fb50da635c6157b942ed",
	}

	vk, err := keys.KeyListFromFolder("./keys_test_folder")

	if err != nil {
		t.Fatalf("failed to read keys from folder: %s", err)
	}
	for i, key := range vk {
		found := false
		for _, expected := range expectedPublicKeys {
			if key.PubKeyToHex() == expected {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected pubkey %s, got %s", expectedPublicKeys[i], key.PubKeyToHex())
		}
	}
}
