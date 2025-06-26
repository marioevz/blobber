package p2p

import (
	fastssz "github.com/prysmaticlabs/fastssz"
)

type Marshaler interface {
	fastssz.Marshaler
	fastssz.Unmarshaler
}

// WrapSpecObject is no longer needed for go-eth2-client types as they implement SSZ marshaling directly
// This function is kept for compatibility but simply returns the object as-is
func WrapSpecObject(spec map[string]interface{}, obj Marshaler) Marshaler {
	// go-eth2-client types already implement the Marshaler interface
	return obj
}

// WrapSSZObject is no longer needed for go-eth2-client types
// This function is kept for compatibility but simply returns the object as-is
func WrapSSZObject(obj Marshaler) Marshaler {
	// go-eth2-client types already implement the Marshaler interface
	return obj
}
