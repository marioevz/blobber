package common

import (
	"encoding/binary"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// GetDomainType extracts a domain type from the spec
func GetDomainType(spec map[string]interface{}, domain string) (phase0.DomainType, error) {
	val, ok := spec[domain]
	if !ok {
		return phase0.DomainType{}, fmt.Errorf("domain type %s not found in spec", domain)
	}

	switch v := val.(type) {
	case phase0.DomainType:
		return v, nil
	case [4]byte:
		return phase0.DomainType(v), nil
	case []byte:
		if len(v) != 4 {
			return phase0.DomainType{}, fmt.Errorf("invalid domain type length: %d", len(v))
		}
		var dt phase0.DomainType
		copy(dt[:], v)
		return dt, nil
	default:
		return phase0.DomainType{}, fmt.Errorf("unexpected type for domain %s: %T", domain, val)
	}
}

// GetForkVersion returns the appropriate fork version for a given slot
func GetForkVersion(spec map[string]interface{}, slot phase0.Slot) (phase0.Version, error) {
	// Get fork epochs from spec
	altairEpoch := GetSpecValue[phase0.Epoch](spec, "ALTAIR_FORK_EPOCH", phase0.Epoch(0))
	bellatrixEpoch := GetSpecValue[phase0.Epoch](spec, "BELLATRIX_FORK_EPOCH", phase0.Epoch(0))
	capellaEpoch := GetSpecValue[phase0.Epoch](spec, "CAPELLA_FORK_EPOCH", phase0.Epoch(0))
	denebEpoch := GetSpecValue[phase0.Epoch](spec, "DENEB_FORK_EPOCH", phase0.Epoch(0))
	electraEpoch := GetSpecValue[phase0.Epoch](spec, "ELECTRA_FORK_EPOCH", phase0.Epoch(0))

	slotsPerEpoch := GetSpecValue[uint64](spec, "SLOTS_PER_EPOCH", 32)
	epoch := phase0.Epoch(uint64(slot) / slotsPerEpoch)

	// Determine fork version based on epoch
	if electraEpoch != 0 && epoch >= electraEpoch {
		return GetForkVersionValue(spec, "ELECTRA_FORK_VERSION")
	} else if denebEpoch != 0 && epoch >= denebEpoch {
		return GetForkVersionValue(spec, "DENEB_FORK_VERSION")
	} else if capellaEpoch != 0 && epoch >= capellaEpoch {
		return GetForkVersionValue(spec, "CAPELLA_FORK_VERSION")
	} else if bellatrixEpoch != 0 && epoch >= bellatrixEpoch {
		return GetForkVersionValue(spec, "BELLATRIX_FORK_VERSION")
	} else if altairEpoch != 0 && epoch >= altairEpoch {
		return GetForkVersionValue(spec, "ALTAIR_FORK_VERSION")
	}

	return GetForkVersionValue(spec, "GENESIS_FORK_VERSION")
}

// GetForkVersionValue extracts a fork version from the spec
func GetForkVersionValue(spec map[string]interface{}, key string) (phase0.Version, error) {
	val, ok := spec[key]
	if !ok {
		return phase0.Version{}, fmt.Errorf("fork version %s not found in spec", key)
	}

	switch v := val.(type) {
	case phase0.Version:
		return v, nil
	case [4]byte:
		return phase0.Version(v), nil
	case []byte:
		if len(v) != 4 {
			return phase0.Version{}, fmt.Errorf("invalid fork version length: %d", len(v))
		}
		var fv phase0.Version
		copy(fv[:], v)
		return fv, nil
	default:
		return phase0.Version{}, fmt.Errorf("unexpected type for fork version %s: %T", key, val)
	}
}

// ComputeDomain computes the domain for a given domain type and fork version
func ComputeDomain(domainType phase0.DomainType, forkVersion phase0.Version, genesisValidatorsRoot phase0.Root) phase0.Domain {
	// Compute fork data root
	forkData := &phase0.ForkData{
		CurrentVersion:        forkVersion,
		GenesisValidatorsRoot: genesisValidatorsRoot,
	}
	forkDataRoot, _ := forkData.HashTreeRoot()

	// Compute domain
	var domain phase0.Domain
	copy(domain[:], domainType[:])
	copy(domain[4:], forkDataRoot[:28])

	return domain
}

// ComputeForkDigest computes the fork digest for a given fork version
func ComputeForkDigest(forkVersion phase0.Version, genesisValidatorsRoot phase0.Root) ([4]byte, error) {
	// Compute fork data root
	forkData := &phase0.ForkData{
		CurrentVersion:        forkVersion,
		GenesisValidatorsRoot: genesisValidatorsRoot,
	}
	forkDataRoot, err := forkData.HashTreeRoot()
	if err != nil {
		return [4]byte{}, err
	}

	// Fork digest is the first 4 bytes of the fork data root
	var digest [4]byte
	copy(digest[:], forkDataRoot[:4])
	return digest, nil
}

// GetSpecValue is a generic helper to extract typed values from spec
func GetSpecValue[T any](spec map[string]interface{}, key string, defaultValue T) T {
	val, ok := spec[key]
	if !ok {
		return defaultValue
	}

	// Try direct type assertion
	if typedVal, ok := val.(T); ok {
		return typedVal
	}

	// Handle numeric conversions
	var result T
	switch any(result).(type) {
	case uint64:
		switch v := val.(type) {
		case int:
			return any(uint64(v)).(T)
		case int64:
			return any(uint64(v)).(T)
		case float64:
			return any(uint64(v)).(T)
		}
	case phase0.Epoch:
		switch v := val.(type) {
		case uint64:
			return any(phase0.Epoch(v)).(T)
		case int:
			return any(phase0.Epoch(v)).(T)
		case int64:
			return any(phase0.Epoch(v)).(T)
		case float64:
			return any(phase0.Epoch(v)).(T)
		}
	}

	return defaultValue
}

// Uint64ToBytes32 converts a uint64 to a 32-byte array (little-endian)
func Uint64ToBytes32(n uint64) [32]byte {
	var b [32]byte
	binary.LittleEndian.PutUint64(b[:8], n)
	return b
}
