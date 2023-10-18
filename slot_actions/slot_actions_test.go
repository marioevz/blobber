package slot_actions_test

import (
	"testing"

	"github.com/marioevz/blobber/slot_actions"
)

func TestSlotActionsJsonParsing(t *testing.T) {
	jsonString := `{
		"name": "broadcast_blobs_before_block"
	}
	`
	act, err := slot_actions.UnmarshallSlotAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallSlotAction() error = %v", err)
	}
	if _, ok := act.(*slot_actions.BroadcastBlobsBeforeBlock); !ok {
		t.Fatalf("UnmarshallSlotAction() wrong type = %t", act)
	}
	jsonString = `{
		"name": "extra_blobs",
		"incorrect_kzg_commitment": true
	}
	`
	act, err = slot_actions.UnmarshallSlotAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallSlotAction() error = %v", err)
	}
	if extraBlobs, ok := act.(*slot_actions.ExtraBlobs); !ok {
		t.Fatalf("UnmarshallSlotAction() wrong type = %t", act)
	} else {
		if extraBlobs.IncorrectKZGCommitment != true {
			t.Fatalf("UnmarshallSlotAction() incorrect_kzg_commitment = %t", extraBlobs.IncorrectKZGCommitment)
		}
	}
	jsonString = `{
		"name": "conflicting_blobs",
		"conflicting_blobs_count": 6,
		"alternate_blob_recipients": true
	}
	`
	act, err = slot_actions.UnmarshallSlotAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallSlotAction() error = %v", err)
	}
	if conflictingBlobs, ok := act.(*slot_actions.ConflictingBlobs); !ok {
		t.Fatalf("UnmarshallSlotAction() wrong type = %t", act)
	} else {
		if conflictingBlobs.ConflictingBlobsCount != 6 {
			t.Fatalf("UnmarshallSlotAction() conflicting_blobs_count = %d", conflictingBlobs.ConflictingBlobsCount)
		}
		if conflictingBlobs.AlternateBlobRecipients != true {
			t.Fatalf("UnmarshallSlotAction() alternate_blob_recipients = %t", conflictingBlobs.AlternateBlobRecipients)
		}
	}
}
