package output

import (
	"encoding/json"
	"io"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/engine"
)

// jsonlSink streams one compact JSON object per line (JSON Lines), using the
// same record shape and redaction boundary as the json format. Unlike the
// json array, a truncated stream stays parseable up to the last full line.
type jsonlSink struct {
	mu  sync.Mutex
	enc *json.Encoder
	err error
}

func newJSONLSink(w io.Writer) *jsonlSink {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &jsonlSink{enc: enc}
}

func (s *jsonlSink) Emit(f engine.Finding) {
	rec := toJSONRecord(f)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return
	}
	s.err = s.enc.Encode(rec)
}

func (s *jsonlSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}
