package connectors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type forgeIncrementalState struct {
	Version int                                    `json:"version"`
	Objects map[string]forgeObjectIncrementalState `json:"objects"`
}

type forgeObjectIncrementalState struct {
	Hash string `json:"hash,omitempty"`
}

type forgeScanState struct {
	previous *forgeIncrementalState
	next     *forgeIncrementalState
}

func loadForgeIncrementalState(raw, provider string) (*forgeIncrementalState, error) {
	if raw == "" {
		return nil, nil
	}
	var state forgeIncrementalState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return nil, fmt.Errorf("%s: parse incremental source state: %w", provider, err)
	}
	if state.Objects == nil {
		state.Objects = map[string]forgeObjectIncrementalState{}
	}
	return &state, nil
}

func emitForgePartIncremental(text string, state *forgeScanState, meta sources.ForgeMeta, emit Emit) error {
	current := forgeStateForText(text)
	if state != nil && state.next != nil {
		state.next.Objects[meta.File] = current
	}
	if state != nil && state.previous != nil && state.previous.Objects[meta.File] == current {
		return nil
	}
	return emit([]byte(text), sources.Metadata{Forge: &meta})
}

func forgeStateForText(text string) forgeObjectIncrementalState {
	sum := sha256.Sum256([]byte(text))
	return forgeObjectIncrementalState{Hash: hex.EncodeToString(sum[:])}
}
