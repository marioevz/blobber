// Package deneb provides dummy types to satisfy imports in dependencies
// This is a workaround for the eth2api dependency that imports old zrnt types
package deneb

// BlobSidecar is a dummy type to satisfy the import in eth2api
type BlobSidecar struct {
	// This is a dummy implementation
}