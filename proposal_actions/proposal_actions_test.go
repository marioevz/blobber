package proposal_actions_test

import (
	"testing"

	"github.com/marioevz/blobber/proposal_actions"
)

func TestProposalActionsJsonParsing(t *testing.T) {
	jsonString := `{
		"broadcast_blobs_first": true
	}
	`
	act, err := proposal_actions.UnmarshallProposalAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallProposalAction() error = %v", err)
	}

	if actCast, ok := act.(proposal_actions.ConfiguredAction).ProposalActionBase.(*proposal_actions.Default); !ok {
		t.Fatalf("UnmarshallProposalAction() wrong type = %t", act)
	} else {
		if actCast.BroadcastBlobsFirst != true {
			t.Fatalf("UnmarshallProposalAction() broadcast_blobs_first = %t", actCast.BroadcastBlobsFirst)
		}
	}

	jsonString = `{
		"name": "blob_gossip_delay",
		"delay_milliseconds": 1000,
		"broadcast_blobs_first": true
	}
	`
	act, err = proposal_actions.UnmarshallProposalAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallProposalAction() error = %v", err)
	}
	if actCast, ok := act.(proposal_actions.ConfiguredAction).ProposalActionBase.(*proposal_actions.BlobGossipDelay); !ok {
		t.Fatalf("UnmarshallProposalAction() wrong type = %t", act)
	} else {
		if actCast.DelayMilliseconds != 1000 {
			t.Fatalf("UnmarshallProposalAction() delay_milliseconds = %d", actCast.DelayMilliseconds)
		}
	}

	jsonString = `{
		"name": "invalid_equivocating_block_and_blobs",
		"broadcast_blobs_first": true,
		"alternate_recipients": true
	}`
	act, err = proposal_actions.UnmarshallProposalAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallProposalAction() error = %v", err)
	}
	if actCast, ok := act.(proposal_actions.ConfiguredAction).ProposalActionBase.(*proposal_actions.InvalidEquivocatingBlockAndBlobs); !ok {
		t.Fatalf("UnmarshallProposalAction() wrong type = %t", act)
	} else {
		if actCast.BroadcastBlobsFirst != true {
			t.Fatalf("UnmarshallProposalAction() broadcast_blobs_first = %t", actCast.BroadcastBlobsFirst)
		}
		if actCast.AlternateRecipients != true {
			t.Fatalf("UnmarshallProposalAction() alternate_recipients = %t", actCast.AlternateRecipients)
		}
	}

	jsonString = `{
		"name": "equivocating_block_header_in_blobs",
		"broadcast_blobs_first": true
	}`
	act, err = proposal_actions.UnmarshallProposalAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallProposalAction() error = %v", err)
	}
	if actCast, ok := act.(proposal_actions.ConfiguredAction).ProposalActionBase.(*proposal_actions.EquivocatingBlockHeaderInBlobs); !ok {
		t.Fatalf("UnmarshallProposalAction() wrong type = %t", act)
	} else {
		if actCast.BroadcastBlobsFirst != true {
			t.Fatalf("UnmarshallProposalAction() broadcast_blobs_first = %t", actCast.BroadcastBlobsFirst)
		}
	}

	jsonString = `{
		"name": "invalid_equivocating_block",
		"correct_block_delay_milliseconds": 1000
	}`
	act, err = proposal_actions.UnmarshallProposalAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallProposalAction() error = %v", err)
	}
	if _, ok := act.(proposal_actions.ConfiguredAction).ProposalActionBase.(*proposal_actions.InvalidEquivocatingBlock); !ok {
		t.Fatalf("UnmarshallProposalAction() wrong type = %t", act)
	}

	jsonString = `{
		"name": "equivocating_blob_sidecars",
		"broadcast_blobs_first": true
	}`
	act, err = proposal_actions.UnmarshallProposalAction([]byte(jsonString))
	if err != nil {
		t.Fatalf("UnmarshallProposalAction() error = %v", err)
	}
	if actCast, ok := act.(proposal_actions.ConfiguredAction).ProposalActionBase.(*proposal_actions.EquivocatingBlobSidecars); !ok {
		t.Fatalf("UnmarshallProposalAction() wrong type = %t", act)
	} else {
		if actCast.BroadcastBlobsFirst != true {
			t.Fatalf("UnmarshallProposalAction() broadcast_blobs_first = %t", actCast.BroadcastBlobsFirst)
		}
	}
}
