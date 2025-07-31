package p2p

import (
	"crypto/ecdsa"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/pkg/errors"
)

// ConvertToInterfacePubkey converts an ECDSA public key to libp2p's crypto.PubKey interface
func ConvertToInterfacePubkey(pubkey *ecdsa.PublicKey) (libp2pcrypto.PubKey, error) {
	if pubkey == nil {
		return nil, errors.New("public key is nil")
	}

	// Create the uncompressed public key format (0x04 + X + Y)
	xBytes := pubkey.X.Bytes()
	yBytes := pubkey.Y.Bytes()

	// Ensure we have 32 bytes for each coordinate
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)

	// Create uncompressed format: 0x04 || X || Y
	pubKeyBytes := make([]byte, 65)
	pubKeyBytes[0] = 0x04
	copy(pubKeyBytes[1:33], xPadded)
	copy(pubKeyBytes[33:65], yPadded)

	// Parse as a libp2p public key
	return libp2pcrypto.UnmarshalSecp256k1PublicKey(pubKeyBytes)
}
