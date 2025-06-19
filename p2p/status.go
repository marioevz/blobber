package p2p

import (
	"sync"

	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/tree"
)

type Status struct {
	*common.Status
	sync.Mutex
}

func NewStatus() *Status {
	return &Status{
		Status: &common.Status{},
		Mutex:  sync.Mutex{},
	}
}

func (s *Status) SetForkDigest(d common.ForkDigest) {
	s.Lock()
	defer s.Unlock()
	s.ForkDigest = d
}

func (s *Status) SetFinalizedCheckpoint(c common.Checkpoint) {
	s.Lock()
	defer s.Unlock()
	s.FinalizedEpoch = c.Epoch
	s.FinalizedRoot = c.Root
}

func (s *Status) SetHead(h tree.Root, slot common.Slot) {
	s.Lock()
	defer s.Unlock()
	s.HeadRoot = h
	s.HeadSlot = slot
}

func (s *Status) GetForkDigest() common.ForkDigest {
	s.Lock()
	defer s.Unlock()
	return s.ForkDigest
}
