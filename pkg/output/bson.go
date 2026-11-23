package output

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/engine"
)

// bsonSink writes one BSON document per finding, concatenated, which is the
// layout `mongoimport --type bson`/`mongorestore` and `bsondump` read. Each
// document carries the exact json/jsonl record (same redaction boundary):
// the record is projected through encoding/json and re-encoded, so the two
// formats cannot drift.
type bsonSink struct {
	mu  sync.Mutex
	w   io.Writer
	err error
}

func newBSONSink(w io.Writer) *bsonSink { return &bsonSink{w: w} }

func (s *bsonSink) Emit(f engine.Finding) {
	rec := toJSONRecord(f)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return
	}
	doc, err := bsonFromJSONValue(rec)
	if err == nil {
		_, err = s.w.Write(doc)
	}
	s.err = err
}

func (s *bsonSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// bsonFromJSONValue encodes v's JSON projection as a BSON document. Object
// keys are sorted for deterministic output.
func bsonFromJSONValue(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return bsonDocument(m)
}

func bsonDocument(m map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var body bytes.Buffer
	for _, k := range keys {
		if err := bsonElement(&body, k, m[k]); err != nil {
			return nil, err
		}
	}
	return bsonWrap(body.Bytes()), nil
}

func bsonWrap(body []byte) []byte {
	out := make([]byte, 4, len(body)+5)
	binary.LittleEndian.PutUint32(out, uint32(len(body)+5))
	out = append(out, body...)
	return append(out, 0)
}

func bsonElement(b *bytes.Buffer, key string, v any) error {
	if strings.IndexByte(key, 0) >= 0 {
		return fmt.Errorf("bson: key contains NUL")
	}
	cstr := func(t byte) { b.WriteByte(t); b.WriteString(key); b.WriteByte(0) }
	switch x := v.(type) {
	case nil:
		cstr(0x0A)
	case bool:
		cstr(0x08)
		if x {
			b.WriteByte(1)
		} else {
			b.WriteByte(0)
		}
	case string:
		cstr(0x02)
		var n [4]byte
		binary.LittleEndian.PutUint32(n[:], uint32(len(x)+1))
		b.Write(n[:])
		b.WriteString(x)
		b.WriteByte(0)
	case json.Number:
		if i, err := x.Int64(); err == nil {
			cstr(0x12)
			var n [8]byte
			binary.LittleEndian.PutUint64(n[:], uint64(i))
			b.Write(n[:])
			return nil
		}
		f, err := x.Float64()
		if err != nil {
			return err
		}
		cstr(0x01)
		var n [8]byte
		binary.LittleEndian.PutUint64(n[:], math.Float64bits(f))
		b.Write(n[:])
	case map[string]any:
		doc, err := bsonDocument(x)
		if err != nil {
			return err
		}
		cstr(0x03)
		b.Write(doc)
	case []any:
		var body bytes.Buffer
		for i, e := range x {
			if err := bsonElement(&body, fmt.Sprint(i), e); err != nil {
				return err
			}
		}
		cstr(0x04)
		b.Write(bsonWrap(body.Bytes()))
	default:
		return fmt.Errorf("bson: unsupported value %T", v)
	}
	return nil
}
