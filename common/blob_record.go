package common

import (
	"sync"

	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
)

type BlobRecord struct {
	sync.RWMutex
	record map[common.Slot][]common.KZGCommitment
}

func NewBlobRecord() *BlobRecord {
	return &BlobRecord{
		record: make(map[common.Slot][]common.KZGCommitment),
	}
}

func (br *BlobRecord) Add(slot common.Slot, blobSidecars ...*deneb.BlobSidecar) {
	br.Lock()
	defer br.Unlock()
	for _, blobSidecar := range blobSidecars {
		br.record[slot] = append(br.record[slot], blobSidecar.KZGCommitment)
	}
}

func (br *BlobRecord) GetSlots() []common.Slot {
	br.RLock()
	defer br.RUnlock()
	var slots []common.Slot
	for slot := range br.record {
		slots = append(slots, slot)
	}
	return slots
}

func GetAllSlots(brAll ...*BlobRecord) []common.Slot {
	slots := make(map[common.Slot]struct{})
	for _, br := range brAll {
		br.RLock()
		for slot := range br.record {
			slots[slot] = struct{}{}
		}
		br.RUnlock()
	}

	var slotsSlice []common.Slot
	for slot := range slots {
		slotsSlice = append(slotsSlice, slot)
	}
	return slotsSlice
}

func (br *BlobRecord) Get(slot common.Slot) []common.KZGCommitment {
	br.RLock()
	defer br.RUnlock()
	return br.record[slot]
}
