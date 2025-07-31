package p2p

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/golang/snappy"
	"github.com/pkg/errors"
)

// ProtocolSuffixSSZSnappy is the suffix for SSZ encoded data with snappy compression
const ProtocolSuffixSSZSnappy = "ssz_snappy"

// SszNetworkEncoder handles SSZ encoding/decoding with snappy compression for network messages
type SszNetworkEncoder struct{}

// EncodeGossip encodes an object to SSZ bytes with snappy compression for gossip
func (e SszNetworkEncoder) EncodeGossip(w io.Writer, msg interface{}) (int, error) {
	b, err := Marshal(msg)
	if err != nil {
		return 0, err
	}
	b = snappy.Encode(nil, b)
	return w.Write(b)
}

// DecodeGossip decodes an object from SSZ bytes with snappy decompression
func (e SszNetworkEncoder) DecodeGossip(b []byte, to interface{}) error {
	b, err := snappy.Decode(nil, b)
	if err != nil {
		return err
	}
	return Unmarshal(b, to)
}

// Marshal encodes a value to SSZ bytes
func Marshal(val interface{}) ([]byte, error) {
	if val == nil {
		return nil, errors.New("cannot marshal nil value")
	}

	// Check if the value implements its own SSZ marshaling
	if marshaler, ok := val.(interface{ MarshalSSZ() ([]byte, error) }); ok {
		return marshaler.MarshalSSZ()
	}

	// Handle basic types
	switch v := val.(type) {
	case uint64:
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, v)
		return buf, nil
	case []byte:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported type for SSZ marshaling: %T", val)
	}
}

// Unmarshal decodes SSZ bytes into a value
func Unmarshal(b []byte, val interface{}) error {
	if val == nil {
		return errors.New("cannot unmarshal into nil value")
	}

	// Check if the value implements its own SSZ unmarshaling
	if unmarshaler, ok := val.(interface{ UnmarshalSSZ([]byte) error }); ok {
		return unmarshaler.UnmarshalSSZ(b)
	}

	// Handle basic types
	switch v := val.(type) {
	case *uint64:
		if len(b) < 8 {
			return errors.New("insufficient bytes for uint64")
		}
		*v = binary.LittleEndian.Uint64(b)
		return nil
	case *[]byte:
		*v = b
		return nil
	default:
		return fmt.Errorf("unsupported type for SSZ unmarshaling: %T", val)
	}
}

// EncodeWithMaxLength encodes a message with a length prefix for req/resp protocols
func (e SszNetworkEncoder) EncodeWithMaxLength(w io.Writer, msg interface{}) (int, error) {
	b, err := Marshal(msg)
	if err != nil {
		return 0, err
	}

	// Compress with snappy
	b = snappy.Encode(nil, b)

	// Create a buffer for the length-prefixed message
	buf := new(bytes.Buffer)

	// Write the length as a varint
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(b))); err != nil {
		return 0, err
	}

	// Write the compressed data
	if _, err := buf.Write(b); err != nil {
		return 0, err
	}

	return w.Write(buf.Bytes())
}

// DecodeWithMaxLength decodes a length-prefixed message for req/resp protocols
func (e SszNetworkEncoder) DecodeWithMaxLength(r io.Reader, val interface{}) error {
	// Read the length prefix
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return errors.Wrap(err, "failed to read length prefix")
	}

	// Sanity check on length (10MB max)
	if length > 10*1024*1024 {
		return fmt.Errorf("message length %d exceeds maximum", length)
	}

	// Read the compressed data
	b := make([]byte, length)
	if _, err := io.ReadFull(r, b); err != nil {
		return errors.Wrap(err, "failed to read message data")
	}

	// Decompress
	b, err := snappy.Decode(nil, b)
	if err != nil {
		return errors.Wrap(err, "failed to decompress message")
	}

	// Unmarshal
	return Unmarshal(b, val)
}
