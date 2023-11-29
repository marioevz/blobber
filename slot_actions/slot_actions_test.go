package slot_actions_test

import (
	"testing"

	"github.com/marioevz/blobber/slot_actions"
)

func TestSlotActionsJsonParsing(t *testing.T) {
	jsonString := `{
		"broadcast_blobs_first": true
	}
	`
	act, err := slot_actions.UnmarshallSlotAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallSlotAction() error = %v", err)
	}
	if actCast, ok := act.(*slot_actions.Default); !ok {
		t.Fatalf("UnmarshallSlotAction() wrong type = %t", act)
	} else {
		if actCast.BroadcastBlobsFirst != true {
			t.Fatalf("UnmarshallSlotAction() broadcast_blobs_first = %t", actCast.BroadcastBlobsFirst)
		}
	}

	jsonString = `{
		"name": "blob_gossip_delay",
		"delay_milliseconds": 1000,
		"broadcast_blobs_first": true
	}
	`
	act, err = slot_actions.UnmarshallSlotAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallSlotAction() error = %v", err)
	}
	if actCast, ok := act.(*slot_actions.BlobGossipDelay); !ok {
		t.Fatalf("UnmarshallSlotAction() wrong type = %t", act)
	} else {
		if actCast.DelayMilliseconds != 1000 {
			t.Fatalf("UnmarshallSlotAction() delay_milliseconds = %d", actCast.DelayMilliseconds)
		}
	}

	jsonString = `{
		"name": "equivocating_block_and_blobs",
		"broadcast_blobs_first": true,
		"alternate_recipients": true
	}`
	act, err = slot_actions.UnmarshallSlotAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallSlotAction() error = %v", err)
	}
	if actCast, ok := act.(*slot_actions.EquivocatingBlockAndBlobs); !ok {
		t.Fatalf("UnmarshallSlotAction() wrong type = %t", act)
	} else {
		if actCast.BroadcastBlobsFirst != true {
			t.Fatalf("UnmarshallSlotAction() broadcast_blobs_first = %t", actCast.BroadcastBlobsFirst)
		}
		if actCast.AlternateRecipients != true {
			t.Fatalf("UnmarshallSlotAction() alternate_recipients = %t", actCast.AlternateRecipients)
		}
	}

	jsonString = `{
		"name": "equivocating_block_header_in_blobs",
		"broadcast_blobs_first": true
	}`
	act, err = slot_actions.UnmarshallSlotAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallSlotAction() error = %v", err)
	}
	if actCast, ok := act.(*slot_actions.EquivocatingBlockHeaderInBlobs); !ok {
		t.Fatalf("UnmarshallSlotAction() wrong type = %t", act)
	} else {
		if actCast.BroadcastBlobsFirst != true {
			t.Fatalf("UnmarshallSlotAction() broadcast_blobs_first = %t", actCast.BroadcastBlobsFirst)
		}
	}

	jsonString = `{
		"name": "invalid_equivocating_block",
		"correct_block_delay_milliseconds": 1000
	}`
	act, err = slot_actions.UnmarshallSlotAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallSlotAction() error = %v", err)
	}
	if _, ok := act.(*slot_actions.InvalidEquivocatingBlock); !ok {
		t.Fatalf("UnmarshallSlotAction() wrong type = %t", act)
	}
}
