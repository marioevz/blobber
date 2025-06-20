package p2p

import (
	"sync"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// Status represents the p2p status message
type StatusData struct {
	ForkDigest     phase0.ForkDigest `json:"fork_digest" yaml:"fork_digest"`
	FinalizedRoot  phase0.Root       `json:"finalized_root" yaml:"finalized_root"`
	FinalizedEpoch phase0.Epoch      `json:"finalized_epoch" yaml:"finalized_epoch"`
	HeadRoot       phase0.Root       `json:"head_root" yaml:"head_root"`
	HeadSlot       phase0.Slot       `json:"head_slot" yaml:"head_slot"`
}

type Status struct {
	*StatusData
	sync.Mutex
}

func NewStatus() *Status {
	return &Status{
		StatusData: &StatusData{},
		Mutex:      sync.Mutex{},
	}
}

func (s *Status) SetForkDigest(d phase0.ForkDigest) {
	s.Lock()
	defer s.Unlock()
	s.ForkDigest = d
}

func (s *Status) SetFinalizedCheckpoint(c phase0.Checkpoint) {
	s.Lock()
	defer s.Unlock()
	s.FinalizedEpoch = c.Epoch
	s.FinalizedRoot = c.Root
}

func (s *Status) SetHead(h phase0.Root, slot phase0.Slot) {
	s.Lock()
	defer s.Unlock()
	s.HeadRoot = h
	s.HeadSlot = slot
}

func (s *Status) GetForkDigest() phase0.ForkDigest {
	s.Lock()
	defer s.Unlock()
	return s.ForkDigest
}
