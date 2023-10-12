package blobber_test

import (
	"testing"

	"github.com/marioevz/blobber/blobber"
)

func TestSlotActionsJsonParsing(t *testing.T) {
	jsonString := `{
		"name": "broadcast_blobs_before_block"
	}
	`
	act, err := blobber.UnmarshallSlotAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallSlotAction() error = %v", err)
	}
	if _, ok := act.(*blobber.BroadcastBlobsBeforeBlock); !ok {
		t.Fatalf("UnmarshallSlotAction() wrong type = %t", act)
	}
	jsonString = `{
		"name": "extra_blobs",
		"incorrect_kzg_commitment": true
	}
	`
	act, err = blobber.UnmarshallSlotAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallSlotAction() error = %v", err)
	}
	if extraBlobs, ok := act.(*blobber.ExtraBlobs); !ok {
		t.Fatalf("UnmarshallSlotAction() wrong type = %t", act)
	} else {
		if extraBlobs.IncorrectKZGCommitment != true {
			t.Fatalf("UnmarshallSlotAction() incorrect_kzg_commitment = %t", extraBlobs.IncorrectKZGCommitment)
		}
	}
}
