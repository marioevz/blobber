package common

import (
	"sync"

	beacon_common "github.com/protolambda/zrnt/eth2/beacon/common"
	eth "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
)

type BlobRecord struct {
	sync.RWMutex
	record map[beacon_common.Slot][]beacon_common.KZGCommitment
}

func NewBlobRecord() *BlobRecord {
	return &BlobRecord{
		record: make(map[beacon_common.Slot][]beacon_common.KZGCommitment),
	}
}

func (br *BlobRecord) Add(slot beacon_common.Slot, blobSidecars ...*eth.BlobSidecar) {
	br.Lock()
	defer br.Unlock()
	for _, blobSidecar := range blobSidecars {
		var kzg beacon_common.KZGCommitment
		copy(kzg[:], blobSidecar.KzgCommitment)
		br.record[slot] = append(br.record[slot], kzg)
	}
}

func (br *BlobRecord) GetSlots() []beacon_common.Slot {
	br.RLock()
	defer br.RUnlock()
	var slots []beacon_common.Slot
	for slot := range br.record {
		slots = append(slots, slot)
	}
	return slots
}

func GetAllSlots(brAll ...*BlobRecord) []beacon_common.Slot {
	slots := make(map[beacon_common.Slot]struct{})
	for _, br := range brAll {
		br.RLock()
		for slot := range br.record {
			slots[slot] = struct{}{}
		}
		br.RUnlock()
	}

	var slotsSlice []beacon_common.Slot
	for slot := range slots {
		slotsSlice = append(slotsSlice, slot)
	}
	return slotsSlice
}

func (br *BlobRecord) Get(slot beacon_common.Slot) []beacon_common.KZGCommitment {
	br.RLock()
	defer br.RUnlock()
	return br.record[slot]
}
