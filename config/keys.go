package config

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/pkg/errors"
	blsu "github.com/protolambda/bls12-381-util"
	keystore "github.com/protolambda/go-keystorev4"
	"github.com/sirupsen/logrus"
)

type ValidatorKey struct {
	// ValidatorSecretKey is the serialized secret key for validator duties
	ValidatorSecretKey [32]byte
	// ValidatorPubkey is the serialized pubkey derived from ValidatorSecretKey
	ValidatorPubkey [48]byte
}

func (vk *ValidatorKey) FromHex(secretKeyHex string) error {
	if vk == nil {
		return errors.New("validator key is nil")
	}
	if secretKeyHex[:2] == "0x" {
		secretKeyHex = secretKeyHex[2:]
	}
	secretKey, err := hex.DecodeString(secretKeyHex)
	if err != nil {
		return errors.Wrap(err, "failed to decode secret key")
	}
	if len(secretKey) != len(vk.ValidatorSecretKey) {
		return fmt.Errorf("invalid secret key length: %d, expected %d", len(secretKey), len(vk.ValidatorSecretKey))
	}
	copy(vk.ValidatorSecretKey[:], secretKey)

	return vk.FillPubKey()
}

func (vk *ValidatorKey) FillPubKey() error {
	sk := new(blsu.SecretKey)
	if err := sk.Deserialize(&vk.ValidatorSecretKey); err != nil {
		return errors.Wrap(err, "failed to deserialize secret key")
	}

	pk, err := blsu.SkToPk(sk)
	if err != nil {
		return errors.Wrap(err, "failed to derive pubkey from secret key")
	}
	pkSerialized := pk.Serialize()
	copy(vk.ValidatorPubkey[:], pkSerialized[:])

	return nil
}

func KeyListFromFile(path string) ([]*ValidatorKey, error) {
	// Read file line by line and parse each line as a validator secret key
	readFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %s", err)
	}
	defer readFile.Close()
	fileScanner := bufio.NewScanner(readFile)

	fileScanner.Split(bufio.ScanLines)

	validatorKeyList := make([]*ValidatorKey, 0)
	for fileScanner.Scan() {
		keyString := strings.TrimSpace(fileScanner.Text())
		if keyString != "" {
			validatorKey := new(ValidatorKey)
			if err := validatorKey.FromHex(keyString); err != nil {
				return nil, errors.Wrap(err, "failed to parse validator key")
			}
			validatorKeyList = append(validatorKeyList, validatorKey)
		}
	}
	return validatorKeyList, nil
}

func KeyListFromFolder(pathStr string) ([]*ValidatorKey, error) {
	// Load keys from a folder that contains a "secrets" and "keys" subdirectories
	secretsDir := path.Join(pathStr, "secrets")
	keysDir := path.Join(pathStr, "keys")

	// Read each file in the secrets directory and parse each line as a validator secret key
	files, err := os.ReadDir(secretsDir)

	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %s", err)
	}

	validatorKeyList := make([]*ValidatorKey, 0)

	for _, file := range files {
		if file.IsDir() {
			// ignore
			continue
		}
		// Read secrets file
		readFile, err := os.Open(path.Join(secretsDir, file.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %s", err)
		}

		// File contains a single line of base64 encoded secret key
		secretKeyBase64, err := io.ReadAll(readFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %s", err)
		}

		keystoreJsonFilePath := path.Join(keysDir, file.Name(), "voting-keystore.json")
		// Read keystore file
		readFile, err = os.Open(keystoreJsonFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %s", err)
		}

		keystoreJson, err := io.ReadAll(readFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %s", err)
		}
		var keystore keystore.Keystore
		if err := json.Unmarshal(keystoreJson, &keystore); err != nil {
			return nil, fmt.Errorf("failed to unmarshal keystore: %s", err)
		}

		// Get secret key from keystore
		secretKey, err := keystore.Decrypt(secretKeyBase64)

		if err != nil {
			return nil, fmt.Errorf("failed to decrypt secret key: %s", err)
		}

		validatorKey := new(ValidatorKey)
		copy(validatorKey.ValidatorSecretKey[:], secretKey)
		if err := validatorKey.FillPubKey(); err != nil {
			return nil, errors.Wrap(err, "failed to parse validator key")
		}
		logrus.WithFields(
			logrus.Fields{
				"ValidatorPubkey": hex.EncodeToString(validatorKey.ValidatorPubkey[:]),
			},
		).Info("Imported validator key to list")
		validatorKeyList = append(validatorKeyList, validatorKey)
	}
	return validatorKeyList, nil
}
