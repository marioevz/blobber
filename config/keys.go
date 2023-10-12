package config

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	blsu "github.com/protolambda/bls12-381-util"
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
