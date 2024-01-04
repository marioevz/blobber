package proposal_actions

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lithammer/dedent"
	"github.com/marioevz/blobber/common"
	"github.com/marioevz/blobber/keys"
	"github.com/marioevz/blobber/p2p"
	"github.com/pkg/errors"
	beacon_common "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
)

const MAX_BLOBS_PER_BLOCK = 6

type ProposalActionBase interface {
	Name() string
	Description() string
	SlotMiss(spec *beacon_common.Spec) bool
	Fields() map[string]interface{}
	GetTestPeerCount() int
	CanExecute(
		spec *beacon_common.Spec,
		beaconBlockContents *deneb.BlockContents,
	) (bool, string)
	Execute(
		spec *beacon_common.Spec,
		testPeers p2p.TestPeers,
		beaconBlockContents *deneb.BlockContents,
		beaconBlockDomain beacon_common.BLSDomain,
		validatorKey *keys.ValidatorKey,
		includeBlobRecord *common.BlobRecord,
		rejectBlobRecord *common.BlobRecord,
	) (bool, error)
}

type ProposalActionResult struct {
	Success    bool   `json:"success"`
	Slot       uint64 `json:"slot"`
	Root       []byte `json:"root"`
	ActionName string `json:"action_name"`
}

type ProposalActionConfiguration interface {
	Frequency() uint64
	SetFrequency(uint64)
	MaxExecutionTimes() uint64
	SetMaxExecutionTimes(uint64)
	TimesExecuted() uint64
	IncrementTimesExecuted()
	SetNextResult(*ProposalActionResult)
	WaitForNextResult(ctx context.Context) (*ProposalActionResult, error)
}

type ProposalAction interface {
	ProposalActionBase
	ProposalActionConfiguration
}

type ProposalActionConfig struct {
	Freq         uint64                     `json:"frequency"`
	MaxExecTimes uint64                     `json:"max_execution_times"`
	Times        uint64                     `json:"-"`
	ResultChan   chan *ProposalActionResult `json:"-"`
}

func (c *ProposalActionConfig) Frequency() uint64 {
	return c.Freq
}

func (c *ProposalActionConfig) SetFrequency(frequency uint64) {
	c.Freq = frequency
}

func (c *ProposalActionConfig) MaxExecutionTimes() uint64 {
	return c.MaxExecTimes
}

func (c *ProposalActionConfig) SetMaxExecutionTimes(maxExecTimes uint64) {
	c.MaxExecTimes = maxExecTimes
}

func (c *ProposalActionConfig) TimesExecuted() uint64 {
	return c.Times
}

func (c *ProposalActionConfig) IncrementTimesExecuted() {
	c.Times++
}

func (c *ProposalActionConfig) SetNextResult(result *ProposalActionResult) {
	if c.ResultChan != nil {
		c.ResultChan <- result
	}
}

func (c *ProposalActionConfig) WaitForNextResult(ctx context.Context) (*ProposalActionResult, error) {
	c.ResultChan = make(chan *ProposalActionResult, 1)
	defer func() {
		c.ResultChan = nil
	}()
	select {
	case result := <-c.ResultChan:
		return result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type ConfiguredAction struct {
	ProposalActionBase
	*ProposalActionConfig
}

func ConfigureProposalAction(proposalActionBase ProposalActionBase, config *ProposalActionConfig) ProposalAction {
	if config == nil {
		config = &ProposalActionConfig{}
	}

	configuredActionObj := ConfiguredAction{
		ProposalActionBase:   proposalActionBase,
		ProposalActionConfig: config,
	}

	return configuredActionObj
}

func UnmarshallProposalAction(data []byte) (ProposalAction, error) {
	if len(data) == 0 {
		return nil, nil
	}

	type actionName struct {
		Name string `json:"name"`
	}
	var actionNameObj actionName
	if err := json.Unmarshal(data, &actionNameObj); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshall proposal action name")
	}

	var action ProposalActionBase
	switch actionNameObj.Name {
	case "blob_gossip_delay":
		action = &BlobGossipDelay{}
	case "equivocating_blob_sidecars":
		action = &EquivocatingBlobSidecars{}
	case "invalid_equivocating_block_and_blobs":
		action = &InvalidEquivocatingBlockAndBlobs{}
	case "equivocating_block_header_in_blobs":
		action = &EquivocatingBlockHeaderInBlobs{}
	case "invalid_equivocating_block":
		action = &InvalidEquivocatingBlock{}
	/*
		case "extra_blobs":
			action = &ExtraBlobs{}
		case "conflicting_blobs":
			action = &ConflictingBlobs{}
		case "swap_blobs":
			action = &SwapBlobs{}
	*/
	default:
		action = &Default{}
	}

	if err := json.Unmarshal(data, &action); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshall proposal action")
	}

	// Unmarshall the configuration
	var config ProposalActionConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshall proposal action config")
	}

	return ConfigureProposalAction(action, &config), nil
}

type Default struct {
	BroadcastBlobsFirst bool `json:"broadcast_blobs_first"`
}

func (s Default) Name() string {
	return "Default"
}

func (s Default) Description() string {
	desc := dedent.Dedent(`
		- Sign the block
		- Generate the blob sidecars using signed header`)
	if s.BroadcastBlobsFirst {
		desc += dedent.Dedent(`
		- Broadcast the blob sidecars
		- Broadcast the block`)
	} else {
		desc += dedent.Dedent(`
		- Broadcast the block
		- Broadcast the blob sidecars`)
	}
	return desc
}

func (s Default) SlotMiss(_ *beacon_common.Spec) bool {
	return false
}

func (s Default) Fields() map[string]interface{} {
	return map[string]interface{}{}
}

func (s Default) GetTestPeerCount() int {
	// By default we only create 1 test p2p and it's connected to all peers
	return 1
}

func (s Default) CanExecute(
	spec *beacon_common.Spec,
	beaconBlockContents *deneb.BlockContents,
) (bool, string) {
	// No checks needed
	return true, ""
}

func (s Default) Execute(
	spec *beacon_common.Spec,
	testPeers p2p.TestPeers,
	beaconBlockContents *deneb.BlockContents,
	beaconBlockDomain beacon_common.BLSDomain,
	validatorKey *keys.ValidatorKey,
	includeBlobRecord *common.BlobRecord,
	rejectBlobRecord *common.BlobRecord,
) (bool, error) {
	// Sign block and create sidecars
	signedBlockBlobsBundle, err := CreatedSignedBlockSidecarsBundle(spec, beaconBlockContents, beaconBlockDomain, validatorKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to create and sign block and blobs")
	}

	// Broadcast the signed block and blobs
	broadcaster := BundleBroadcaster{
		Spec:       spec,
		Peers:      testPeers,
		BlobsFirst: s.BroadcastBlobsFirst,
	}
	if err = broadcaster.Broadcast(signedBlockBlobsBundle); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block and blob sidecars")
	}
	if !s.SlotMiss(spec) {
		// Add the blobs to the must-include blob record
		includeBlobRecord.Add(beaconBlockContents.Block.Slot, signedBlockBlobsBundle.BlobSidecars...)
	}
	return true, nil
}

type BlobGossipDelay struct {
	Default
	DelayMilliseconds int `json:"delay_milliseconds"`
}

func (s BlobGossipDelay) Name() string {
	return "Blob gossip delay"
}

func (s BlobGossipDelay) Description() string {
	return fmt.Sprintf(dedent.Dedent(`
		- Sign the block
		- Generate the blob sidecars using signed header
		- Broadcast the block
		- Insert a delay of %d milliseconds
		- Broadcast the blob sidecars`), s.DelayMilliseconds)
}

func (s BlobGossipDelay) SlotMiss(spec *beacon_common.Spec) bool {
	// Consider a slot miss only if the delay is more than half a slot
	return s.DelayMilliseconds >= int(spec.SECONDS_PER_SLOT*1000)/2
}

func (s BlobGossipDelay) Fields() map[string]interface{} {
	return map[string]interface{}{
		"delay_milliseconds": s.DelayMilliseconds,
	}
}

func (s BlobGossipDelay) CanExecute(
	spec *beacon_common.Spec,
	beaconBlockContents *deneb.BlockContents,
) (bool, string) {
	// We require at least 1 blob to be able to delay gossiping it
	if len(beaconBlockContents.Blobs) == 0 {
		return false, "no blobs"
	}
	return true, ""
}

func (s BlobGossipDelay) Execute(
	spec *beacon_common.Spec,
	testPeers p2p.TestPeers,
	beaconBlockContents *deneb.BlockContents,
	beaconBlockDomain beacon_common.BLSDomain,
	validatorKey *keys.ValidatorKey,
	includeBlobRecord *common.BlobRecord,
	rejectBlobRecord *common.BlobRecord,
) (bool, error) {
	// Sign block and create sidecars
	signedBlockBlobsBundle, err := CreatedSignedBlockSidecarsBundle(spec, beaconBlockContents, beaconBlockDomain, validatorKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to create and sign block and blobs")
	}

	// Broadcast the signed block and blobs
	broadcaster := BundleBroadcaster{
		Spec:              spec,
		Peers:             testPeers,
		BlobsFirst:        s.BroadcastBlobsFirst,
		DelayMilliseconds: s.DelayMilliseconds,
	}
	if err = broadcaster.Broadcast(signedBlockBlobsBundle); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block and blob sidecars")
	}
	if !s.SlotMiss(spec) {
		// Add the blobs to the must-include blob record
		includeBlobRecord.Add(beaconBlockContents.Block.Slot, signedBlockBlobsBundle.BlobSidecars...)
	}
	return true, nil
}

type EquivocatingBlobSidecars struct {
	Default
	BroadcastBlobsFirst bool `json:"broadcast_blobs_first"`
}

func (s EquivocatingBlobSidecars) Name() string {
	return "Equivocating Blob Sidecars"
}

func (s EquivocatingBlobSidecars) Description() string {
	desc := dedent.Dedent(`
	- Create an equivocating block by modifying the graffiti
	- Sign both blocks
	- Generate blob sidecar bundles out of both signed blocks`)
	if s.BroadcastBlobsFirst {
		desc += dedent.Dedent(`
		- Broadcast both blob sidecar bundles to different peers
		- Broadcast the original signed block only`)
	} else {
		desc += dedent.Dedent(`
		- Broadcast the original signed block only
		- Broadcast both blob sidecar bundles to different peers`)
	}
	return desc
}

func (s EquivocatingBlobSidecars) Fields() map[string]interface{} {
	return map[string]interface{}{}
}

func (s EquivocatingBlobSidecars) GetTestPeerCount() int {
	// We are going to send two conflicting blob sidecar bundles through two different test p2p connections
	return 2
}

func (s EquivocatingBlobSidecars) CanExecute(
	spec *beacon_common.Spec,
	beaconBlockContents *deneb.BlockContents,
) (bool, string) {
	// We require at least 1 blob to create the equivocating blob sidecars
	if len(beaconBlockContents.Blobs) == 0 {
		return false, "no blobs"
	}
	return true, ""
}

func (s EquivocatingBlobSidecars) Execute(
	spec *beacon_common.Spec,
	testPeers p2p.TestPeers,
	beaconBlockContents *deneb.BlockContents,
	beaconBlockDomain beacon_common.BLSDomain,
	validatorKey *keys.ValidatorKey,
	includeBlobRecord *common.BlobRecord,
	rejectBlobRecord *common.BlobRecord,
) (bool, error) {
	if len(testPeers) != 2 {
		return false, fmt.Errorf("expected 2 test p2p connections, got %d", len(testPeers))
	}
	// Sign the blocks (original and equivocating) and generate the sidecars
	signedBlockBlobsBundles, err := CreateSignEquivocatingBlock(spec, beaconBlockContents, beaconBlockDomain, validatorKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to create and sign equivocating block")
	}

	// Create a bundle of the original block but use the sidecars generated by the
	// equivocating block
	equivBlobsSignedBlockBundle := &SignedBlockSidecarsBundle{
		SignedBlock:  signedBlockBlobsBundles[0].SignedBlock,
		BlobSidecars: signedBlockBlobsBundles[1].BlobSidecars,
	}

	// The correct blobs are the ones generated by the original block
	correctBlobsSignedBlockBundle := signedBlockBlobsBundles[0]

	// Broadcast the signed block and blobs
	broadcaster := BundleBroadcaster{
		Spec:       spec,
		Peers:      testPeers,
		BlobsFirst: s.BroadcastBlobsFirst,
	}
	if err := broadcaster.Broadcast(equivBlobsSignedBlockBundle, correctBlobsSignedBlockBundle); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block")
	}

	return true, nil
}

type InvalidEquivocatingBlockAndBlobs struct {
	Default
	BroadcastBlobsFirst bool `json:"broadcast_blobs_first"`
	// TODO: ModifyBlobs         bool `json:"modify_blobs"`
	// TODO: ModifyKZGProofs     bool `json:"modify_kzg_proofs"`
	AlternateRecipients bool `json:"alternate_recipients"`
}

func (s InvalidEquivocatingBlockAndBlobs) Name() string {
	return "Equivocating Block and Blobs"
}

func (s InvalidEquivocatingBlockAndBlobs) Description() string {
	desc := dedent.Dedent(`
	- Create an equivocating block by modifying the graffiti
	- Sign both blocks
	- Generate blob sidecars for both blocks`)
	if s.BroadcastBlobsFirst {
		desc += dedent.Dedent(`
		- Broadcast the blob sidecars for both blocks to different peers
		- Broadcast the signed blocks to different peers`)
	} else {
		desc += dedent.Dedent(`
		- Broadcast the signed blocks to different peers
		- Broadcast the blob sidecars for both blocks to different peers`)
	}
	if s.AlternateRecipients {
		desc += dedent.Dedent(`
		- Alternate the recipients of the blocks and blobs every time the action is executed`)
	}
	return desc
}

func (s InvalidEquivocatingBlockAndBlobs) Fields() map[string]interface{} {
	return map[string]interface{}{}
}

func (s InvalidEquivocatingBlockAndBlobs) GetTestPeerCount() int {
	// We are going to send two conflicting blocks and sets of blobs through two different test p2p connections
	return 2
}

func (s InvalidEquivocatingBlockAndBlobs) CanExecute(
	spec *beacon_common.Spec,
	beaconBlockContents *deneb.BlockContents,
) (bool, string) {
	// We require at least 1 blob to create the equivocating blob sidecars
	if len(beaconBlockContents.Blobs) == 0 {
		return false, "no blobs"
	}
	return true, ""
}

func (s InvalidEquivocatingBlockAndBlobs) Execute(
	spec *beacon_common.Spec,
	testPeers p2p.TestPeers,
	beaconBlockContents *deneb.BlockContents,
	beaconBlockDomain beacon_common.BLSDomain,
	validatorKey *keys.ValidatorKey,
	includeBlobRecord *common.BlobRecord,
	rejectBlobRecord *common.BlobRecord,
) (bool, error) {
	if len(testPeers) != 2 {
		return false, fmt.Errorf("expected 2 test p2p connections, got %d", len(testPeers))
	}
	// Sign the blocks (original and equivocating) and generate the sidecars
	signedBlockBlobsBundles, err := CreateSignEquivocatingBlock(spec, beaconBlockContents, beaconBlockDomain, validatorKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to create and sign equivocating block")
	}

	if s.AlternateRecipients && (beaconBlockContents.Block.Slot%2 == 0) {
		signedBlockBlobsBundles[0], signedBlockBlobsBundles[1] = signedBlockBlobsBundles[1], signedBlockBlobsBundles[0]
	}

	// Broadcast the signed block and blobs
	broadcaster := BundleBroadcaster{
		Spec:       spec,
		Peers:      testPeers,
		BlobsFirst: s.BroadcastBlobsFirst,
	}
	if err := broadcaster.Broadcast(signedBlockBlobsBundles...); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block")
	}

	return true, nil
}

type EquivocatingBlockHeaderInBlobs struct {
	Default
	BroadcastBlobsFirst bool `json:"broadcast_blobs_first"`
}

func (s EquivocatingBlockHeaderInBlobs) Name() string {
	return "Equivocating Block Header in Blobs"
}

func (s EquivocatingBlockHeaderInBlobs) Description() string {
	desc := dedent.Dedent(`
	- Create an invalid equivocating block by modifying the graffiti
	- Sign both blocks
	- Generate the sidecars out of the equivocating signed block only`)
	if s.BroadcastBlobsFirst {
		desc += dedent.Dedent(`
		- Broadcast the blob sidecars with the equivocating block header
		- Broadcast the original signed block only`)
	} else {
		desc += dedent.Dedent(`
		- Broadcast the original signed block only
		- Broadcast the blob sidecars with the equivocating block header`)
	}
	return desc
}

func (s EquivocatingBlockHeaderInBlobs) Fields() map[string]interface{} {
	return map[string]interface{}{}
}

func (s EquivocatingBlockHeaderInBlobs) CanExecute(
	spec *beacon_common.Spec,
	beaconBlockContents *deneb.BlockContents,
) (bool, string) {
	// We require at least 1 blob
	if len(beaconBlockContents.Blobs) == 0 {
		return false, "no blobs"
	}
	return true, ""
}

func (s EquivocatingBlockHeaderInBlobs) Execute(
	spec *beacon_common.Spec,
	testPeers p2p.TestPeers,
	beaconBlockContents *deneb.BlockContents,
	beaconBlockDomain beacon_common.BLSDomain,
	validatorKey *keys.ValidatorKey,
	includeBlobRecord *common.BlobRecord,
	rejectBlobRecord *common.BlobRecord,
) (bool, error) {
	// Sign the blocks (original and equivocating) and generate the sidecars
	signedBlockBlobsBundles, err := CreateSignEquivocatingBlock(spec, beaconBlockContents, beaconBlockDomain, validatorKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to create and sign equivocating block")
	}

	// Create a bundle of the original block but use the sidecars generated by the
	// equivocating block
	signedBlockSidecarBundle := &SignedBlockSidecarsBundle{
		SignedBlock:  signedBlockBlobsBundles[0].SignedBlock,
		BlobSidecars: signedBlockBlobsBundles[1].BlobSidecars,
	}

	// Broadcast the signed block and blobs
	broadcaster := BundleBroadcaster{
		Spec:       spec,
		Peers:      testPeers,
		BlobsFirst: s.BroadcastBlobsFirst,
	}
	if err := broadcaster.Broadcast(signedBlockSidecarBundle); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block")
	}

	// Add the blobs to the must-reject blob record
	rejectBlobRecord.Add(beaconBlockContents.Block.Slot, signedBlockBlobsBundles[0].BlobSidecars...)
	rejectBlobRecord.Add(beaconBlockContents.Block.Slot, signedBlockBlobsBundles[1].BlobSidecars...)

	return true, nil
}

type InvalidEquivocatingBlock struct {
	Default
}

func (s InvalidEquivocatingBlock) Name() string {
	return "Invalid Equivocating Block"
}

func (s InvalidEquivocatingBlock) Description() string {
	desc := dedent.Dedent(`
	- Create an invalid equivocating block by modifying the graffiti
	- Sign both blocks
	- Generate the sidecars out of the correct block only
	- Broadcast the blob sidecars
	- Broadcast the equivocating signed block and the correct signed block to different peers`)
	return desc
}

func (s InvalidEquivocatingBlock) Fields() map[string]interface{} {
	return map[string]interface{}{}
}

func (s InvalidEquivocatingBlock) GetTestPeerCount() int {
	// We are going to send two conflicting blocks through two different test p2p connections
	return 2
}

func (s InvalidEquivocatingBlock) CanExecute(
	spec *beacon_common.Spec,
	beaconBlockContents *deneb.BlockContents,
) (bool, string) {
	// No requirements
	return true, ""
}

func (s InvalidEquivocatingBlock) Execute(
	spec *beacon_common.Spec,
	testPeers p2p.TestPeers,
	beaconBlockContents *deneb.BlockContents,
	beaconBlockDomain beacon_common.BLSDomain,
	validatorKey *keys.ValidatorKey,
	includeBlobRecord *common.BlobRecord,
	rejectBlobRecord *common.BlobRecord,
) (bool, error) {
	if len(testPeers) != 2 {
		return false, fmt.Errorf("expected 2 test p2p connections, got %d", len(testPeers))
	}
	// Sign the blocks (original and equivocating) and generate the sidecars
	signedBlockBlobsBundles, err := CreateSignEquivocatingBlock(spec, beaconBlockContents, beaconBlockDomain, validatorKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to create and sign equivocating block")
	}

	correctBlockBundle, equivocatingBlockBundle := signedBlockBlobsBundles[0], signedBlockBlobsBundles[1]

	// Create a bundle of the original block but use the sidecars generated by the
	// equivocating block
	signedBlockSidecarBundle := &SignedBlockSidecarsBundle{
		SignedBlock:  equivocatingBlockBundle.SignedBlock,
		BlobSidecars: correctBlockBundle.BlobSidecars,
	}

	// Broadcast the signed block and blobs
	broadcaster := BundleBroadcaster{
		Spec:       spec,
		Peers:      testPeers,
		BlobsFirst: true,
	}
	if err := broadcaster.Broadcast(signedBlockSidecarBundle, correctBlockBundle); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block")
	}

	if !s.SlotMiss(spec) {
		// Add the blobs to the must-include blob record
		includeBlobRecord.Add(beaconBlockContents.Block.Slot, correctBlockBundle.BlobSidecars...)
	}

	return true, nil
}

type InvalidBlobSidecar struct {
	Default
}

/*
Invalidation types:
- blob_sidecar.index >= MAX_BLOBS_PER_BLOCK
- Invalid subnet
- blob_sidecar.signed_block_header.signature is invalid
- Invalidate sidecar inclusion proof
- Invalidate sidecar kzg commitment
*/

/*
TODO: Refactor all of this

- Send all the correct blobs but with the equivocating block header

type ExtraBlobs struct {
	Default
	IncorrectKZGCommitment  bool `json:"incorrect_kzg_commitment"`
	IncorrectKZGProof       bool `json:"incorrect_kzg_proof"`
	IncorrectBlockRoot      bool `json:"incorrect_block_root"`
	IncorrectSignature      bool `json:"incorrect_signature"`
	DelayMilliseconds       int  `json:"delay_milliseconds"`
	BroadcastBlockFirst     bool `json:"broadcast_block_last"`
	BroadcastExtraBlobFirst bool `json:"broadcast_extra_blob_last"`
}

func (s ExtraBlobs) Name() string {
	return "Extra blobs"
}

func (s ExtraBlobs) Fields() map[string]interface{} {
	return map[string]interface{}{
		"incorrect_kzg_commitment":   s.IncorrectKZGCommitment,
		"incorrect_kzg_proof":        s.IncorrectKZGProof,
		"incorrect_block_root":       s.IncorrectBlockRoot,
		"incorrect_signature":        s.IncorrectSignature,
		"delay_milliseconds":         s.DelayMilliseconds,
		"broadcast_block_first":      s.BroadcastBlockFirst,
		"broadcast_extra_blob_first": s.BroadcastExtraBlobFirst,
	}
}

func FillSidecarWithRandomBlob(sidecar *deneb.BlobSidecar) error {
	blob, kgzCommitment, kzgProof, err := kzg.RandomBlob()
	if err != nil {
		return errors.Wrap(err, "failed to generate random blob")
	}
	sidecar.Blob = blob[:]
	copy(sidecar.KZGCommitment[:], kgzCommitment[:])
	copy(sidecar.KZGProof[:], kzgProof[:])
	return nil
}

func (s ExtraBlobs) Execute(
	spec *beacon_common.Spec,
	testPeers p2p.TestPeers,
	beaconBlockContents *deneb.BlockContents,
	beaconBlockDomain beacon_common.BLSDomain,
	validatorKey *keys.ValidatorKey,
	includeBlobRecord *common.BlobRecord,
	rejectBlobRecord *common.BlobRecord,
) (bool, error) {
	// Sign block
	signedBlockContents, err := SignBlockContents(spec, beaconBlockContents, beaconBlockDomain, validatorKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign block")
	}
	signedBlobs, err := SignBlobs(blobSidecars, blobSidecarDomain, validatorKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign blobs")
	}

	// Generate the extra blob sidecar
	extraBlobSidecar := &deneb.BlobSidecar{
		Slot:            beaconBlock.Slot,
		BlockParentRoot: beaconBlock.ParentRoot[:],
		ProposerIndex:   beaconBlock.ProposerIndex,
	}

	if s.IncorrectBlockRoot {
		extraBlobSidecar.BlockRoot = make([]byte, 32)
		rand.Read(extraBlobSidecar.BlockRoot)
	} else {
		blockRoot, err := beaconBlock.HashTreeRoot()
		if err != nil {
			return false, errors.Wrap(err, "failed to get block hash tree root")
		}
		extraBlobSidecar.BlockRoot = blockRoot[:]
	}

	if err := FillSidecarWithRandomBlob(extraBlobSidecar); err != nil {
		return false, errors.Wrap(err, "failed to fill extra blob sidecar")
	}

	if s.IncorrectKZGCommitment {
		fields := logrus.Fields{
			"correct": fmt.Sprintf("%x", extraBlobSidecar.KZGCommitment),
		}
		rand.Read(extraBlobSidecar.KZGCommitment)
		fields["corrupted"] = fmt.Sprintf("%x", extraBlobSidecar.KZGCommitment)
		logrus.WithFields(fields).Debug("Corrupted blob sidecar kzg commitment")
	}

	if s.IncorrectKZGProof {
		fields := logrus.Fields{
			"correct": fmt.Sprintf("%x", extraBlobSidecar.KZGProof),
		}
		rand.Read(extraBlobSidecar.KZGProof)
		fields["corrupted"] = fmt.Sprintf("%x", extraBlobSidecar.KZGProof)
		logrus.WithFields(fields).Debug("Corrupted blob sidecar kzg proof")
	}

	// Sign the blob
	signedExtraBlob, err := SignBlob(extraBlobSidecar, blobSidecarDomain, validatorKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign extra blob")
	}

	if s.IncorrectSignature {
		fields := logrus.Fields{
			"correct": fmt.Sprintf("%x", signedExtraBlob.Signature),
		}
		rand.Read(signedExtraBlob.Signature)
		fields["corrupted"] = fmt.Sprintf("%x", signedExtraBlob.Signature)
		logrus.WithFields(fields).Debug("Corrupted blob sidecar signature")
	}

	logrus.WithFields(
		logrus.Fields{
			"blockRoot":       fmt.Sprintf("%x", extraBlobSidecar.BlockRoot),
			"blockParentRoot": fmt.Sprintf("%x", extraBlobSidecar.BlockParentRoot),
			"slot":            extraBlobSidecar.Slot,
			"proposerIndex":   extraBlobSidecar.ProposerIndex,
			"kzgCommitment":   fmt.Sprintf("%x", extraBlobSidecar.KZGCommitment),
			"kzgProof":        fmt.Sprintf("%x", extraBlobSidecar.KZGProof),
		},
	).Debug("Extra blob")

	if s.BroadcastBlockFirst {
		// Broadcast the block
		if err := testPeers.BroadcastSignedBeaconBlock(signedBlock); err != nil {
			return false, errors.Wrap(err, "failed to broadcast signed beacon block")
		}
	}

	if s.BroadcastExtraBlobFirst {
		// Broadcast the extra blob
		if err := testPeers.BroadcastSignedBlobSidecar(signedExtraBlob, nil); err != nil {
			return false, errors.Wrap(err, "failed to broadcast extra signed blob sidecar")
		}

		// Insert a delay before gossiping the blobs
		time.Sleep(time.Duration(s.DelayMilliseconds) * time.Millisecond)
	}

	// Broadcast the correct blobs
	if err := testPeers.BroadcastSignedBlobSidecars(signedBlobs); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed blob sidecar")
	}

	if !s.BroadcastExtraBlobFirst {
		// Insert a delay before gossiping the blobs
		time.Sleep(time.Duration(s.DelayMilliseconds) * time.Millisecond)

		// Broadcast the extra blob
		if err := testPeers.BroadcastSignedBlobSidecar(signedExtraBlob, nil); err != nil {
			return false, errors.Wrap(err, "failed to broadcast extra signed blob sidecar")
		}
	}

	if !s.BroadcastBlockFirst {
		// Broadcast the block
		if err := testPeers.BroadcastSignedBeaconBlock(signedBlock); err != nil {
			return false, errors.Wrap(err, "failed to broadcast signed beacon block")
		}
	}

	// Add the blobs to the must-include blob record
	includeBlobRecord.Add(beaconBlockContents.Block.Slot, blobSidecars...)

	// Add the extra blob to the must-reject blob record
	rejectBlobRecord.Add(beaconBlockContents.Block.Slot, extraBlobSidecar)

	return true, nil
}


type ConflictingBlobs struct {
	Default
	ConflictingBlobsCount       int  `json:"conflicting_blobs_count"`
	RandomConflictingBlobsCount bool `json:"random_conflicting_blobs_count"`
	AlternateBlobRecipients     bool `json:"alternate_blob_recipients"`
}

func (s ConflictingBlobs) Name() string {
	return "Conflicting blobs"
}

func (s ConflictingBlobs) Fields() map[string]interface{} {
	return map[string]interface{}{
		"conflicting_blobs_count":        s.ConflictingBlobsCount,
		"random_conflicting_blobs_count": s.RandomConflictingBlobsCount,
		"alternate_blob_recipients":      s.AlternateBlobRecipients,
	}
}

func (s ConflictingBlobs) GetTestPeerCount() int {
	// We are going to send two conflicting blobs through two different test p2p connections
	return 2
}

func (s ConflictingBlobs) GetConflictingBlobsCount() int {
	if s.RandomConflictingBlobsCount {
		return math_rand.Intn(MAX_BLOBS_PER_BLOCK-1) + 1
	}
	if s.ConflictingBlobsCount > 0 {
		return s.ConflictingBlobsCount
	}
	return 1
}

func (s ConflictingBlobs) Execute(
	spec *beacon_common.Spec,
	testPeers p2p.TestPeers,
	beaconBlockContents *deneb.BlockContents,
	beaconBlockDomain beacon_common.BLSDomain,
	validatorKey *keys.ValidatorKey,
	includeBlobRecord *common.BlobRecord,
	rejectBlobRecord *common.BlobRecord,
) (bool, error) {
	if len(testPeers) != 2 {
		return false, fmt.Errorf("expected 2 test p2p connections, got %d", len(testPeers))
	}

	// Sign block
	signedBlockContents, err := SignBlockContents(spec, beaconBlockContents, beaconBlockDomain, validatorKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign block")
	}
	signedBlobs, err := SignBlobs(blobSidecars, blobSidecarDomain, validatorKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign blobs")
	}

	// Generate the extra blob sidecars
	blockRoot, err := beaconBlock.HashTreeRoot()
	if err != nil {
		return false, errors.Wrap(err, "failed to get block hash tree root")
	}

	conflictingBlobsCount := s.GetConflictingBlobsCount()

	// Create the second list of sidecars
	secondBlobSidecarsLength := len(signedBlobs)
	if secondBlobSidecarsLength < conflictingBlobsCount {
		secondBlobSidecarsLength = conflictingBlobsCount
	}
	secondBlobSidecars := make([]*eth.SignedBlobSidecar, secondBlobSidecarsLength)

	for i := 0; i < secondBlobSidecarsLength; i++ {
		if i < conflictingBlobsCount {
			conflictingBlobSidecar := &deneb.BlobSidecar{
				BlockRoot:       blockRoot[:],
				Index:           uint64(i),
				Slot:            beaconBlock.Slot,
				BlockParentRoot: beaconBlock.ParentRoot[:],
				ProposerIndex:   beaconBlock.ProposerIndex,
			}

			if err := FillSidecarWithRandomBlob(conflictingBlobSidecar); err != nil {
				return false, errors.Wrap(err, "failed to fill extra blob sidecar")
			}
			// Sign the blob
			secondBlobSidecars[i], err = SignBlob(conflictingBlobSidecar, blobSidecarDomain, validatorKey)
			if err != nil {
				return false, errors.Wrap(err, "failed to sign extra blob")
			}

			// Add the blob to the must-reject blob record
			rejectBlobRecord.Add(beaconBlockContents.Block.Slot, conflictingBlobSidecar)
		} else {
			secondBlobSidecars[i] = signedBlobs[i]
		}
	}

	var signedBlobsBundles [][]*eth.SignedBlobSidecar
	if s.AlternateBlobRecipients && (beaconBlock.Slot%2 == 0) {
		signedBlobsBundles = [][]*eth.SignedBlobSidecar{secondBlobSidecars, signedBlobs}
	} else {
		signedBlobsBundles = [][]*eth.SignedBlobSidecar{signedBlobs, secondBlobSidecars}
	}
	if err := MultiPeerSignedBlobBroadcast(spec, testPeers, signedBlobsBundles); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed blob sidecars")
	}

	// Broadcast the block
	if err := testPeers.BroadcastSignedBeaconBlock(signedBlock); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block")
	}

	// Add the blobs to the must-include blob record
	includeBlobRecord.Add(beaconBlockContents.Block.Slot, blobSidecars...)

	return true, nil
}

// Send all correct blobs but swap the indexes of two blobs
// Split network: send the correct blobs to one half of the peers and the swapped blobs to
// the other half
type SwapBlobs struct {
	Default
	SplitNetwork bool `json:"split_network"`
}

func (s SwapBlobs) Name() string {
	return "Swap blobs"
}

func (s SwapBlobs) Fields() map[string]interface{} {
	return map[string]interface{}{
		"split_network": s.SplitNetwork,
	}
}

func (s SwapBlobs) GetTestPeerCount() int {
	// We are going to send conflicting blobs if the network is split
	if s.SplitNetwork {
		return 2
	}
	return 1
}

func (s SwapBlobs) ModifyBlobs(blobSidecars []*deneb.BlobSidecar) ([]*deneb.BlobSidecar, error) {
	modifiedBlobSidecars, err := CopyBlobSidecars(blobSidecars)
	if err != nil {
		return nil, errors.Wrap(err, "failed to copy blobs")
	}

	if len(blobSidecars) > 0 {
		// If we only have one blob, we can simply modify the index of this single blob
		if len(blobSidecars) == 1 {
			modifiedBlobSidecars[0].Index = 1
		} else {
			// Swap the indexes of two blobs
			firstIndex := math_rand.Intn(len(blobSidecars))
			secondIndex := math_rand.Intn(len(blobSidecars))
			for firstIndex == secondIndex {
				secondIndex = math_rand.Intn(len(blobSidecars))
			}
			modifiedBlobSidecars[firstIndex].Index = uint64(secondIndex)
			modifiedBlobSidecars[secondIndex].Index = uint64(firstIndex)

			// Swap the blobs (So they are sent in increased index order)
			tmpBlob := modifiedBlobSidecars[firstIndex]
			modifiedBlobSidecars[firstIndex] = modifiedBlobSidecars[secondIndex]
			modifiedBlobSidecars[secondIndex] = tmpBlob
		}
	}
	return modifiedBlobSidecars, nil
}

func (s SwapBlobs) Execute(
	spec *beacon_common.Spec,
	testPeers p2p.TestPeers,
	beaconBlockContents *deneb.BlockContents,
	beaconBlockDomain beacon_common.BLSDomain,
	validatorKey *keys.ValidatorKey,
	includeBlobRecord *common.BlobRecord,
	rejectBlobRecord *common.BlobRecord,
) (bool, error) {
	var (
		signedBlock          *eth.SignedBeaconBlockDeneb
		signedBlobs          []*eth.SignedBlobSidecar
		signedModifiedBlobs  []*eth.SignedBlobSidecar
		modifiedBlobSidecars []*deneb.BlobSidecar
		err                  error
	)

	if s.SplitNetwork && len(testPeers) != 2 {
		return false, fmt.Errorf("expected 2 test p2p connections, got %d", len(testPeers))
	}

	// Modify the blobs
	modifiedBlobSidecars, err = s.ModifyBlobs(blobSidecars)
	if err != nil {
		return false, errors.Wrap(err, "failed to modify blobs")
	}

	// Sign block
	signedBlock, err = SignBlock(spec, beaconBlock, beaconBlockDomain, validatorKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign block")
	}
	if s.SplitNetwork {
		signedBlobs, err = SignBlobs(blobSidecars, blobSidecarDomain, validatorKey)
		if err != nil {
			return false, errors.Wrap(err, "failed to sign blobs")
		}
	}
	signedModifiedBlobs, err = SignBlobs(modifiedBlobSidecars, blobSidecarDomain, validatorKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign modified blobs")
	}

	// Broadcast the blob sidecars first for the test to make sense
	if s.SplitNetwork {
		if err := MultiPeerSignedBlobBroadcast(spec, testPeers, [][]*eth.SignedBlobSidecar{signedBlobs, signedModifiedBlobs}); err != nil {
			return false, errors.Wrap(err, "failed to broadcast signed blob sidecars")
		}
	} else {
		if err := testPeers.BroadcastSignedBlobSidecars(signedModifiedBlobs); err != nil {
			return false, errors.Wrap(err, "failed to broadcast signed blob sidecars")
		}
	}

	// Broadcast the block
	if err := testPeers.BroadcastSignedBeaconBlock(signedBlock); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block")
	}

	// Add the blobs to the records
	if s.SplitNetwork {
		// The signed blobs with the correct indexes do make their way into the network, so they must be present in the block
		includeBlobRecord.Add(beaconBlockContents.Block.Slot, blobSidecars...)
	} else {
		// Only the modified invalid blob sidecars make their way into the network, so they shouldn't be present in the block
		rejectBlobRecord.Add(beaconBlockContents.Block.Slot, modifiedBlobSidecars...)
	}

	return true, nil
}
*/
