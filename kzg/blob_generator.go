package kzg

import (
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"

	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/pkg/errors"
)

var gCryptoCtx gokzg4844.Context
var initCryptoCtx sync.Once

//go:embed trusted_setup.json
var content embed.FS

// InitializeCryptoCtx initializes the global context object returned via CryptoCtx
func InitializeCryptoCtx() {
	initCryptoCtx.Do(func() {
		// Initialize context to match the configurations that the
		// specs are using.
		config, err := content.ReadFile("trusted_setup.json")
		if err != nil {
			panic(err)
		}
		params := new(gokzg4844.JSONTrustedSetup)
		if err = json.Unmarshal(config, params); err != nil {
			panic(err)
		}
		ctx, err := gokzg4844.NewContext4096(params)
		if err != nil {
			panic(fmt.Sprintf("could not create context, err : %v", err))
		}
		gCryptoCtx = *ctx
		// Initialize the precompile return value
	})
}

// CryptoCtx returns a context object stores all of the necessary configurations
// to allow one to create and verify blob proofs.
// This function is expensive to run if the crypto context isn't initialized, so it is recommended to
// pre-initialize by calling InitializeCryptoCtx
func CryptoCtx() gokzg4844.Context {
	InitializeCryptoCtx()
	return gCryptoCtx
}

type BlobID uint64

func (blobId BlobID) FillBlob(blob *gokzg4844.Blob) error {
	if blob == nil {
		return errors.New("blob is nil")
	}
	if blobId == 0 {
		// Blob zero is empty blob, so leave as is
		return nil
	}
	// Fill the blob with deterministic data
	blobIdBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blobIdBytes, uint64(blobId))

	// First 32 bytes are the hash of the blob ID
	currentHashed := sha256.Sum256(blobIdBytes)

	for scalarIndex := 0; scalarIndex < gokzg4844.ScalarsPerBlob; scalarIndex++ {
		copy(blob[scalarIndex*32:(scalarIndex+1)*32], currentHashed[:])

		// Check that no 32 bytes chunks are greater than the BLS modulus
		for i := 0; i < 32; i++ {
			//blobByteIdx := ((scalarIndex + 1) * 32) - i - 1
			blobByteIdx := (scalarIndex * 32) + i
			if blob[blobByteIdx] < gokzg4844.BlsModulus[i] {
				// go to next chunk
				break
			} else if blob[blobByteIdx] >= gokzg4844.BlsModulus[i] {
				if gokzg4844.BlsModulus[i] > 0 {
					// This chunk is greater than the modulus, and we can reduce it in this byte position
					blob[blobByteIdx] = gokzg4844.BlsModulus[i] - 1
					// go to next chunk
					break
				} else {
					// This chunk is greater than the modulus, but we can't reduce it in this byte position, so we will try in the next byte position
					blob[blobByteIdx] = gokzg4844.BlsModulus[i]
				}
			}
		}

		// Hash the current hash
		currentHashed = sha256.Sum256(currentHashed[:])
	}

	return nil
}

func (blobId BlobID) GenerateBlob() (*gokzg4844.Blob, *gokzg4844.KZGCommitment, *gokzg4844.KZGProof, error) {
	blob := gokzg4844.Blob{}
	if err := blobId.FillBlob(&blob); err != nil {
		return nil, nil, nil, errors.Wrap(err, "error filling blob")
	}
	ctx_4844 := CryptoCtx()

	kzgCommitment, err := ctx_4844.BlobToKZGCommitment(&blob, 0)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "error computing kzg commitment")
	}

	proof, err := ctx_4844.ComputeBlobKZGProof(&blob, kzgCommitment, 1)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "error computing kzg proof")
	}

	return &blob, &kzgCommitment, &proof, nil
}

func RandomBlob() (*gokzg4844.Blob, *gokzg4844.KZGCommitment, *gokzg4844.KZGProof, error) {
	return BlobID(rand.Uint64()).GenerateBlob()
}
