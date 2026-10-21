package common

import (
	"math"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

func TestGetSlotDuration(t *testing.T) {
	hezeSpec := map[string]interface{}{
		"SECONDS_PER_SLOT":      12 * time.Second,
		"SLOT_DURATION_MS":      uint64(12000),
		"SLOTS_PER_EPOCH":       uint64(32),
		"HEZE_FORK_EPOCH":       uint64(5),
		"SLOT_DURATION_MS_HEZE": uint64(9000),
	}
	noHezeDurationSpec := map[string]interface{}{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOT_DURATION_MS": uint64(12000),
		"SLOTS_PER_EPOCH":  uint64(32),
		"HEZE_FORK_EPOCH":  uint64(5),
	}
	farFutureSpec := map[string]interface{}{
		"SECONDS_PER_SLOT":      12 * time.Second,
		"SLOT_DURATION_MS":      uint64(12000),
		"SLOTS_PER_EPOCH":       uint64(32),
		"HEZE_FORK_EPOCH":       uint64(math.MaxUint64),
		"SLOT_DURATION_MS_HEZE": uint64(9000),
	}

	tests := []struct {
		name string
		spec map[string]interface{}
		slot phase0.Slot
		want time.Duration
	}{
		{"pre-fork", hezeSpec, 159, 12 * time.Second},
		{"fork slot", hezeSpec, 160, 9 * time.Second},
		{"post-fork", hezeSpec, 1000, 9 * time.Second},
		{"heze duration absent", noHezeDurationSpec, 1000, 12 * time.Second},
		{"heze far future", farFutureSpec, math.MaxUint64, 12 * time.Second},
		{"seconds per slot only", map[string]interface{}{"SECONDS_PER_SLOT": 6 * time.Second}, 1000, 6 * time.Second},
		{"empty spec", map[string]interface{}{}, 1000, 12 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetSlotDuration(tt.spec, tt.slot); got != tt.want {
				t.Errorf("GetSlotDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}
