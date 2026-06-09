package connectors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type siemIncrementalState struct {
	Version int                                  `json:"version"`
	Events  map[string]siemEventIncrementalState `json:"events"`
}

type siemEventIncrementalState struct {
	Hash      string `json:"hash"`
	Timestamp string `json:"timestamp,omitempty"`
}

type siemScanState struct {
	previous *siemIncrementalState
	next     *siemIncrementalState
}

func loadSIEMIncrementalState(raw, provider string) (*siemIncrementalState, error) {
	if raw == "" {
		return nil, nil
	}
	var state siemIncrementalState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return nil, fmt.Errorf("%s: invalid incremental state: %w", provider, err)
	}
	if state.Events == nil {
		state.Events = map[string]siemEventIncrementalState{}
	}
	return &state, nil
}

func emitSIEMIncremental(key string, data []byte, timestamp string, state *siemScanState, meta sources.Metadata, emit Emit) error {
	current := siemEventState(data, timestamp)
	state.next.Events[key] = current
	if state.previous != nil {
		if prev, ok := state.previous.Events[key]; ok && prev == current {
			return nil
		}
	}
	return emit(data, meta)
}

func siemEventState(data []byte, timestamp string) siemEventIncrementalState {
	sum := sha256.Sum256(data)
	return siemEventIncrementalState{Hash: hex.EncodeToString(sum[:]), Timestamp: timestamp}
}

func siemContentKey(prefix string, data []byte) string {
	sum := sha256.Sum256(data)
	return prefix + ":" + hex.EncodeToString(sum[:])
}

func writeSIEMFingerprintEvent(h hash.Hash, key string, data []byte, timestamp string) {
	writeFingerprint(h, key)
	writeFingerprint(h, timestamp)
	sum := sha256.Sum256(data)
	writeFingerprint(h, hex.EncodeToString(sum[:]))
}
