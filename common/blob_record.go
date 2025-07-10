package common

import (
	"sync"

	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

type BlobRecord struct {
	sync.RWMutex
	record map[phase0.Slot][]deneb.KZGCommitment
}

func NewBlobRecord() *BlobRecord {
	return &BlobRecord{
		record: make(map[phase0.Slot][]deneb.KZGCommitment),
	}
}

func (br *BlobRecord) Add(slot phase0.Slot, blobSidecars ...*deneb.BlobSidecar) {
	br.Lock()
	defer br.Unlock()
	for _, blobSidecar := range blobSidecars {
		br.record[slot] = append(br.record[slot], blobSidecar.KZGCommitment)
	}
}

func (br *BlobRecord) GetSlots() []phase0.Slot {
	br.RLock()
	defer br.RUnlock()
	var slots []phase0.Slot
	for slot := range br.record {
		slots = append(slots, slot)
	}
	return slots
}

func GetAllSlots(brAll ...*BlobRecord) []phase0.Slot {
	slots := make(map[phase0.Slot]struct{})
	for _, br := range brAll {
		br.RLock()
		for slot := range br.record {
			slots[slot] = struct{}{}
		}
		br.RUnlock()
	}

	var slotsSlice []phase0.Slot
	for slot := range slots {
		slotsSlice = append(slotsSlice, slot)
	}
	return slotsSlice
}

func (br *BlobRecord) Get(slot phase0.Slot) []deneb.KZGCommitment {
	br.RLock()
	defer br.RUnlock()
	return br.record[slot]
}
