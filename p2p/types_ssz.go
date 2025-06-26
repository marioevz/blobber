package p2p

import (
	"encoding/binary"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/prysmaticlabs/fastssz"
)

// MarshalSSZ serializes the StatusData object
func (s *StatusData) MarshalSSZ() ([]byte, error) {
	buf := make([]byte, s.SizeSSZ())
	_, err := s.MarshalSSZTo(buf[:0])
	return buf, err
}

// MarshalSSZTo serializes the StatusData object to a target array
func (s *StatusData) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// Field (0) 'ForkDigest'
	dst = append(dst, s.ForkDigest[:]...)

	// Field (1) 'FinalizedRoot'
	dst = append(dst, s.FinalizedRoot[:]...)

	// Field (2) 'FinalizedEpoch'
	epochBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(epochBuf, uint64(s.FinalizedEpoch))
	dst = append(dst, epochBuf...)

	// Field (3) 'HeadRoot'
	dst = append(dst, s.HeadRoot[:]...)

	// Field (4) 'HeadSlot'
	slotBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(slotBuf, uint64(s.HeadSlot))
	dst = append(dst, slotBuf...)

	return
}

// UnmarshalSSZ deserializes the StatusData object
func (s *StatusData) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size != 84 {
		return ssz.ErrSize
	}

	// Field (0) 'ForkDigest'
	copy(s.ForkDigest[:], buf[0:4])

	// Field (1) 'FinalizedRoot'
	copy(s.FinalizedRoot[:], buf[4:36])

	// Field (2) 'FinalizedEpoch'
	s.FinalizedEpoch = phase0.Epoch(binary.LittleEndian.Uint64(buf[36:44]))

	// Field (3) 'HeadRoot'
	copy(s.HeadRoot[:], buf[44:76])

	// Field (4) 'HeadSlot'
	s.HeadSlot = phase0.Slot(binary.LittleEndian.Uint64(buf[76:84]))

	return err
}

// SizeSSZ returns the SSZ encoded size in bytes for the StatusData object
func (s *StatusData) SizeSSZ() (size int) {
	size = 84
	return
}

// HashTreeRoot computes the SSZ hash tree root of the StatusData object
func (s *StatusData) HashTreeRoot() ([32]byte, error) {
	hh := ssz.NewHasher()
	if err := s.HashTreeRootWith(hh); err != nil {
		return [32]byte{}, err
	}
	return hh.HashRoot()
}

// HashTreeRootWith computes the SSZ hash tree root of the StatusData object with a custom hasher
func (s *StatusData) HashTreeRootWith(hh *ssz.Hasher) (err error) {
	indx := hh.Index()

	// Field (0) 'ForkDigest'
	hh.PutBytes(s.ForkDigest[:])

	// Field (1) 'FinalizedRoot'
	hh.PutBytes(s.FinalizedRoot[:])

	// Field (2) 'FinalizedEpoch'
	hh.PutUint64(uint64(s.FinalizedEpoch))

	// Field (3) 'HeadRoot'
	hh.PutBytes(s.HeadRoot[:])

	// Field (4) 'HeadSlot'
	hh.PutUint64(uint64(s.HeadSlot))

	hh.Merkleize(indx)
	return
}

// MarshalSSZ serializes the Metadata object
func (m *Metadata) MarshalSSZ() ([]byte, error) {
	buf := make([]byte, m.SizeSSZ())
	_, err := m.MarshalSSZTo(buf[:0])
	return buf, err
}

// MarshalSSZTo serializes the Metadata object to a target array
func (m *Metadata) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// Field (0) 'SeqNumber'
	seqBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(seqBuf, m.SeqNumber)
	dst = append(dst, seqBuf...)

	// Field (1) 'Attnets'
	dst = append(dst, m.Attnets[:]...)

	// Field (2) 'Syncnets'
	dst = append(dst, m.Syncnets[:]...)

	return
}

// UnmarshalSSZ deserializes the Metadata object
func (m *Metadata) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size != 17 {
		return ssz.ErrSize
	}

	// Field (0) 'SeqNumber'
	m.SeqNumber = binary.LittleEndian.Uint64(buf[0:8])

	// Field (1) 'Attnets'
	copy(m.Attnets[:], buf[8:16])

	// Field (2) 'Syncnets'
	copy(m.Syncnets[:], buf[16:17])

	return err
}

// SizeSSZ returns the SSZ encoded size in bytes for the Metadata object
func (m *Metadata) SizeSSZ() (size int) {
	size = 17
	return
}

// HashTreeRoot computes the SSZ hash tree root of the Metadata object
func (m *Metadata) HashTreeRoot() ([32]byte, error) {
	hh := ssz.NewHasher()
	if err := m.HashTreeRootWith(hh); err != nil {
		return [32]byte{}, err
	}
	return hh.HashRoot()
}

// HashTreeRootWith computes the SSZ hash tree root of the Metadata object with a custom hasher
func (m *Metadata) HashTreeRootWith(hh *ssz.Hasher) (err error) {
	indx := hh.Index()

	// Field (0) 'SeqNumber'
	hh.PutUint64(m.SeqNumber)

	// Field (1) 'Attnets'
	hh.PutBytes(m.Attnets[:])

	// Field (2) 'Syncnets'
	hh.PutBytes(m.Syncnets[:])

	hh.Merkleize(indx)
	return
}

// MarshalSSZ serializes the Goodbye object
func (g *Goodbye) MarshalSSZ() ([]byte, error) {
	buf := make([]byte, g.SizeSSZ())
	_, err := g.MarshalSSZTo(buf[:0])
	return buf, err
}

// MarshalSSZTo serializes the Goodbye object to a target array
func (g *Goodbye) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	tmp := make([]byte, 8)
	binary.LittleEndian.PutUint64(tmp, uint64(*g))
	dst = append(dst, tmp...)
	return
}

// UnmarshalSSZ deserializes the Goodbye object
func (g *Goodbye) UnmarshalSSZ(buf []byte) error {
	if len(buf) != 8 {
		return ssz.ErrSize
	}
	*g = Goodbye(binary.LittleEndian.Uint64(buf))
	return nil
}

// SizeSSZ returns the SSZ encoded size in bytes for the Goodbye object
func (g *Goodbye) SizeSSZ() int {
	return 8
}

// HashTreeRoot computes the SSZ hash tree root of the Goodbye object
func (g *Goodbye) HashTreeRoot() ([32]byte, error) {
	hh := ssz.NewHasher()
	if err := g.HashTreeRootWith(hh); err != nil {
		return [32]byte{}, err
	}
	return hh.HashRoot()
}

// HashTreeRootWith computes the SSZ hash tree root of the Goodbye object with a custom hasher
func (g *Goodbye) HashTreeRootWith(hh *ssz.Hasher) error {
	hh.PutUint64(uint64(*g))
	return nil
}

// MarshalSSZ serializes the Ping object
func (p *Ping) MarshalSSZ() ([]byte, error) {
	buf := make([]byte, p.SizeSSZ())
	_, err := p.MarshalSSZTo(buf[:0])
	return buf, err
}

// MarshalSSZTo serializes the Ping object to a target array
func (p *Ping) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	tmp := make([]byte, 8)
	binary.LittleEndian.PutUint64(tmp, uint64(*p))
	dst = append(dst, tmp...)
	return
}

// UnmarshalSSZ deserializes the Ping object
func (p *Ping) UnmarshalSSZ(buf []byte) error {
	if len(buf) != 8 {
		return ssz.ErrSize
	}
	*p = Ping(binary.LittleEndian.Uint64(buf))
	return nil
}

// SizeSSZ returns the SSZ encoded size in bytes for the Ping object
func (p *Ping) SizeSSZ() int {
	return 8
}

// HashTreeRoot computes the SSZ hash tree root of the Ping object
func (p *Ping) HashTreeRoot() ([32]byte, error) {
	hh := ssz.NewHasher()
	if err := p.HashTreeRootWith(hh); err != nil {
		return [32]byte{}, err
	}
	return hh.HashRoot()
}

// HashTreeRootWith computes the SSZ hash tree root of the Ping object with a custom hasher
func (p *Ping) HashTreeRootWith(hh *ssz.Hasher) error {
	hh.PutUint64(uint64(*p))
	return nil
}
