package common

import (
	"sync"

	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/tree"
)

//go:generate go run github.com/prysmaticlabs/fastssz/sszgen --path $GOFILE

type Status struct {
	ForkDigest     []byte `json:"fork_digest" ssz-size:"4"`
	FinalizedRoot  []byte `json:"finalized_root" ssz-size:"32"`
	FinalizedEpoch uint64 `json:"finalized_epoch"`
	HeadRoot       []byte `json:"head_root" ssz-size:"32"`
	HeadSlot       uint64 `json:"head_slot"`

	sync.Mutex `json:"-"`
}

func NewStatus() *Status {
	return &Status{
		ForkDigest:    make([]byte, len(common.ForkDigest{})),
		FinalizedRoot: make([]byte, len(common.Root{})),
		HeadRoot:      make([]byte, len(common.Root{})),
	}
}

func (s *Status) SetForkDigest(d common.ForkDigest) {
	s.Lock()
	defer s.Unlock()
	copy(s.ForkDigest, d[:])
}

func (s *Status) SetFinalizedCheckpoint(c common.Checkpoint) {
	s.Lock()
	defer s.Unlock()
	copy(s.FinalizedRoot, c.Root[:])
	s.FinalizedEpoch = uint64(c.Epoch)
}

func (s *Status) SetHead(h tree.Root, slot common.Slot) {
	s.Lock()
	defer s.Unlock()
	copy(s.HeadRoot, h[:])
	s.HeadSlot = uint64(slot)
}

func (s *Status) GetForkDigest() common.ForkDigest {
	s.Lock()
	defer s.Unlock()
	var d common.ForkDigest
	copy(d[:], s.ForkDigest)
	return d
}
