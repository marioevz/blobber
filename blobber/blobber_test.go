package blobber_test

import (
	"bytes"
	_ "embed"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/marioevz/blobber/blobber"
)

//go:embed response_deneb.json
var responseDeneb string

func TestResponseParse(T *testing.T) {
	version, blockBlobResponse, err := blobber.ParseResponse([]byte(responseDeneb))
	if err != nil {
		T.Fatal(err)
	} else if blockBlobResponse == nil {
		T.Fatal("block is nil")
	}
	if version != "deneb" {
		T.Fatalf("wrong version: %s, expected deneb", version)
	}

	if len(blockBlobResponse.Blobs) != 6 {
		T.Fatalf("wrong number of sidecars: %d, expected 5", len(blockBlobResponse.Blobs))
	}

	expectedBlockRoot := common.HexToHash("0x37977b8edac80973deb38f3888bff9483b45b057c188ec041273cfe4485e2695")

	blockRoot := blockBlobResponse.Blobs[0].BlockRoot
	if !bytes.Equal(expectedBlockRoot[:], blockRoot[:]) {
		T.Fatalf("wrong block root: %x, expected %x", blockRoot[:], expectedBlockRoot[:])
	}
}
