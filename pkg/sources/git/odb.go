package git

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// In-process packed object reader for the patch renderer (#983).
//
// Blobs are read straight from mmapped pack files: no pipe, no per-worker
// helper process, and one delta-base cache shared by every renderer of the
// walk. Only what the renderer needs is modelled — version 2 index files,
// SHA-1 object ids, OFS/REF deltas inside one pack. Loose objects, other
// hash functions, and anything malformed report errODBMiss so the commit
// falls back to git's own rendering.

var errODBMiss = errors.New("object not readable in process")

const (
	odbObjCommit   = 1
	odbObjTree     = 2
	odbObjBlob     = 3
	odbObjTag      = 4
	odbObjOfsDelta = 6
	odbObjRefDelta = 7
)

type odbPack struct {
	pack   []byte
	idx    []byte
	n      uint32
	fanout []byte
	names  []byte
	offs   []byte
	large  []byte
	unmap  []func() error
}

type objectDB struct {
	packs   []*odbPack
	cache   *odbCache
	zr      sync.Pool
	scratch sync.Pool // *[]byte delta buffers
}

// openObjectDB maps every pack under objectsDir and its alternates. It
// returns nil when nothing can be read in process.
func openObjectDB(objectsDir string, cacheBytes int64) (*objectDB, error) {
	db := &objectDB{cache: newODBCache(cacheBytes)}
	db.scratch.New = func() any { b := make([]byte, 0, 64<<10); return &b }
	seen := map[string]bool{}
	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		dir = filepath.Clean(dir)
		if seen[dir] || depth > 5 {
			return nil
		}
		seen[dir] = true
		names, _ := filepath.Glob(filepath.Join(dir, "pack", "pack-*.idx"))
		sort.Strings(names)
		for _, idx := range names {
			p, err := openODBPack(idx, strings.TrimSuffix(idx, ".idx")+".pack")
			if err != nil {
				db.close()
				return err
			}
			db.packs = append(db.packs, p)
		}
		alt, err := os.ReadFile(filepath.Join(dir, "info", "alternates"))
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(string(alt), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line[0] == '#' || line[0] == '"' {
				continue
			}
			if !filepath.IsAbs(line) {
				line = filepath.Join(dir, line)
			}
			if err := walk(line, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(objectsDir, 0); err != nil {
		return nil, err
	}
	if len(db.packs) == 0 {
		return nil, nil
	}
	return db, nil
}

func openODBPack(idxPath, packPath string) (*odbPack, error) {
	idx, unIdx, err := mmapFile(idxPath)
	if err != nil {
		return nil, err
	}
	p := &odbPack{idx: idx, unmap: []func() error{unIdx}}
	pack, unPack, err := mmapFile(packPath)
	if err != nil {
		p.close()
		return nil, err
	}
	p.pack = pack
	p.unmap = append(p.unmap, unPack)
	if len(idx) < 8+256*4 || !bytes.Equal(idx[:8], []byte{0xff, 't', 'O', 'c', 0, 0, 0, 2}) ||
		len(pack) < 12+20 || !bytes.Equal(pack[:4], []byte("PACK")) {
		p.close()
		return nil, fmt.Errorf("git: unsupported pack %s", filepath.Base(packPath))
	}
	p.fanout = idx[8 : 8+256*4]
	p.n = binary.BigEndian.Uint32(p.fanout[255*4:])
	n := int(p.n)
	base := 8 + 256*4
	need := base + n*20 + n*4 + n*4 + 40
	if len(idx) < need {
		p.close()
		return nil, fmt.Errorf("git: truncated pack index %s", filepath.Base(idxPath))
	}
	p.names = idx[base : base+n*20]
	p.offs = idx[base+n*24 : base+n*28]
	p.large = idx[base+n*28 : len(idx)-40]
	return p, nil
}

func (p *odbPack) close() {
	for _, f := range p.unmap {
		_ = f()
	}
	p.unmap = nil
}

func (db *objectDB) close() {
	if db == nil {
		return
	}
	for _, p := range db.packs {
		p.close()
	}
	db.packs = nil
}

func (p *odbPack) find(id []byte) (int64, bool) {
	lo := uint32(0)
	if id[0] > 0 {
		lo = binary.BigEndian.Uint32(p.fanout[(int(id[0])-1)*4:])
	}
	hi := binary.BigEndian.Uint32(p.fanout[int(id[0])*4:])
	for lo < hi {
		mid := (lo + hi) / 2
		c := bytes.Compare(p.names[mid*20:mid*20+20], id)
		switch {
		case c == 0:
			return p.offset(mid)
		case c < 0:
			lo = mid + 1
		default:
			hi = mid
		}
	}
	return 0, false
}

func (p *odbPack) offset(i uint32) (int64, bool) {
	o := binary.BigEndian.Uint32(p.offs[i*4:])
	if o&0x80000000 == 0 {
		return int64(o), true
	}
	j := int(o&0x7fffffff) * 8
	if j+8 > len(p.large) {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(p.large[j:])), true
}

// readBlob returns the blob's content in buf (reallocated when needed). A
// result that is not a blob, or exceeds limit, reports errODBMiss.
func (db *objectDB) readBlob(oid string, limit int64, buf []byte) ([]byte, error) {
	var id [20]byte
	if len(oid) != 40 {
		return nil, errODBMiss
	}
	if _, err := hex.Decode(id[:], []byte(oid)); err != nil {
		return nil, errODBMiss
	}
	for pi, p := range db.packs {
		off, ok := p.find(id[:])
		if !ok {
			continue
		}
		typ, data, err := db.object(pi, off, limit, 0, buf[:0])
		if err != nil {
			return nil, err
		}
		if typ != odbObjBlob || int64(len(data)) > limit {
			return nil, errODBMiss
		}
		return data, nil
	}
	return nil, errODBMiss
}

// header parses the object header at off.
func (p *odbPack) header(off int64) (typ int, size int64, data int64, err error) {
	if off < 12 || off >= int64(len(p.pack)) {
		return 0, 0, 0, errODBMiss
	}
	b := p.pack[off:]
	c := b[0]
	typ = int(c>>4) & 7
	size = int64(c & 15)
	shift := uint(4)
	i := 1
	for c&0x80 != 0 {
		if i >= len(b) || shift > 56 {
			return 0, 0, 0, errODBMiss
		}
		c = b[i]
		i++
		size |= int64(c&0x7f) << shift
		shift += 7
	}
	return typ, size, off + int64(i), nil
}

// object reconstructs the object at off. With a non-nil dst the result is
// written into dst's storage and owned by the caller; with a nil dst it is
// freshly allocated or shared with the cache, and must not be modified.
func (db *objectDB) object(pi int, off int64, limit int64, depth int, dst []byte) (int, []byte, error) {
	if depth > 128 {
		return 0, nil, errODBMiss
	}
	if typ, data, ok := db.cache.get(pi, off); ok {
		if dst != nil {
			if int64(len(data)) > limit {
				return typ, nil, errODBMiss
			}
			data = append(dst[:0], data...)
		}
		return typ, data, nil
	}
	p := db.packs[pi]
	typ, size, pos, err := p.header(off)
	if err != nil {
		return 0, nil, err
	}
	switch typ {
	case odbObjCommit, odbObjTree, odbObjBlob, odbObjTag:
		if size > limit {
			return typ, nil, errODBMiss
		}
		data, err := db.inflate(p, pos, size, dst)
		if err != nil {
			return 0, nil, err
		}
		return typ, data, nil
	case odbObjOfsDelta, odbObjRefDelta:
	default:
		return 0, nil, errODBMiss
	}
	var baseOff int64
	if typ == odbObjOfsDelta {
		b := p.pack
		if pos >= int64(len(b)) {
			return 0, nil, errODBMiss
		}
		c := b[pos]
		pos++
		rel := int64(c & 0x7f)
		for c&0x80 != 0 {
			if pos >= int64(len(b)) || rel > 1<<55 {
				return 0, nil, errODBMiss
			}
			c = b[pos]
			pos++
			rel = ((rel + 1) << 7) | int64(c&0x7f)
		}
		baseOff = off - rel
	} else {
		if pos+20 > int64(len(p.pack)) {
			return 0, nil, errODBMiss
		}
		var ok bool
		baseOff, ok = p.find(p.pack[pos : pos+20])
		if !ok {
			// Thin packs never reach a repository; other packs are out of scope.
			return 0, nil, errODBMiss
		}
		pos += 20
	}
	if size > 1<<31 {
		return 0, nil, errODBMiss
	}
	scratch := db.scratch.Get().(*[]byte)
	defer db.scratch.Put(scratch)
	delta, err := db.inflate(p, pos, size, (*scratch)[:0])
	if err != nil {
		return 0, nil, err
	}
	*scratch = delta
	btyp, base, err := db.object(pi, baseOff, 1<<62, depth+1, nil)
	if err != nil {
		return 0, nil, err
	}
	// The base is likely shared with sibling deltas: keep it.
	db.cache.put(pi, baseOff, btyp, base)
	out, err := applyDelta(base, delta, limit, dst)
	if err != nil {
		return 0, nil, err
	}
	return btyp, out, nil
}

// growBuf returns dst resized to n, reusing its storage when it fits.
func growBuf(dst []byte, n int64) []byte {
	if dst != nil && int64(cap(dst)) >= n {
		return dst[:n]
	}
	return make([]byte, n)
}

func (db *objectDB) inflate(p *odbPack, pos, size int64, dst []byte) ([]byte, error) {
	if pos >= int64(len(p.pack)) {
		return nil, errODBMiss
	}
	src := bytes.NewReader(p.pack[pos:])
	var zr io.ReadCloser
	if v := db.zr.Get(); v != nil {
		zr = v.(io.ReadCloser)
		if err := zr.(zlib.Resetter).Reset(src, nil); err != nil {
			return nil, errODBMiss
		}
	} else {
		var err error
		if zr, err = zlib.NewReader(src); err != nil {
			return nil, errODBMiss
		}
	}
	defer db.zr.Put(zr)
	out := growBuf(dst, size)
	if _, err := io.ReadFull(zr, out); err != nil {
		return nil, errODBMiss
	}
	return out, nil
}

func deltaVarint(d []byte, i int) (int64, int, bool) {
	var v int64
	shift := uint(0)
	for {
		if i >= len(d) || shift > 56 {
			return 0, i, false
		}
		c := d[i]
		i++
		v |= int64(c&0x7f) << shift
		shift += 7
		if c&0x80 == 0 {
			return v, i, true
		}
	}
}

func applyDelta(base, d []byte, limit int64, dst []byte) ([]byte, error) {
	srcSize, i, ok := deltaVarint(d, 0)
	if !ok || srcSize != int64(len(base)) {
		return nil, errODBMiss
	}
	dstSize, i, ok := deltaVarint(d, i)
	if !ok || dstSize > limit {
		return nil, errODBMiss
	}
	out := growBuf(dst, dstSize)[:0]
	for i < len(d) {
		c := d[i]
		i++
		if c&0x80 != 0 {
			var off, n uint32
			for k := uint(0); k < 4; k++ {
				if c&(1<<k) != 0 {
					if i >= len(d) {
						return nil, errODBMiss
					}
					off |= uint32(d[i]) << (8 * k)
					i++
				}
			}
			for k := uint(0); k < 3; k++ {
				if c&(0x10<<k) != 0 {
					if i >= len(d) {
						return nil, errODBMiss
					}
					n |= uint32(d[i]) << (8 * k)
					i++
				}
			}
			if n == 0 {
				n = 0x10000
			}
			if uint64(off)+uint64(n) > uint64(len(base)) || int64(len(out))+int64(n) > dstSize {
				return nil, errODBMiss
			}
			out = append(out, base[off:off+n]...)
		} else if c != 0 {
			if i+int(c) > len(d) || int64(len(out))+int64(c) > dstSize {
				return nil, errODBMiss
			}
			out = append(out, d[i:i+int(c)]...)
			i += int(c)
		} else {
			return nil, errODBMiss
		}
	}
	if int64(len(out)) != dstSize {
		return nil, errODBMiss
	}
	return out, nil
}

// odbCache is a bounded, sharded cache of reconstructed delta bases.
type odbCache struct {
	shards [64]odbCacheShard
}

type odbCacheKey struct {
	pack int
	off  int64
}

type odbCacheEntry struct {
	typ  int
	data []byte
	tick uint64
}

type odbCacheShard struct {
	mu    sync.Mutex
	m     map[odbCacheKey]*odbCacheEntry
	bytes int64
	limit int64
	tick  uint64
}

func newODBCache(total int64) *odbCache {
	c := &odbCache{}
	for i := range c.shards {
		c.shards[i].m = make(map[odbCacheKey]*odbCacheEntry)
		c.shards[i].limit = total / int64(len(c.shards))
	}
	return c
}

func (c *odbCache) shard(off int64) *odbCacheShard {
	return &c.shards[(uint64(off)*0x9e3779b97f4a7c15)>>58]
}

func (c *odbCache) get(pack int, off int64) (int, []byte, bool) {
	s := c.shard(off)
	s.mu.Lock()
	e, ok := s.m[odbCacheKey{pack, off}]
	if ok {
		s.tick++
		e.tick = s.tick
	}
	s.mu.Unlock()
	if !ok {
		return 0, nil, false
	}
	return e.typ, e.data, true
}

func (c *odbCache) put(pack int, off int64, typ int, data []byte) {
	s := c.shard(off)
	sz := int64(len(data))
	if sz > s.limit/4 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := odbCacheKey{pack, off}
	if _, ok := s.m[k]; ok {
		return
	}
	for s.bytes+sz > s.limit && len(s.m) > 0 {
		// Evict the least recently used of a small sample.
		var victim odbCacheKey
		var oldest *odbCacheEntry
		n := 0
		for k2, e := range s.m {
			if oldest == nil || e.tick < oldest.tick {
				victim, oldest = k2, e
			}
			if n++; n >= 8 {
				break
			}
		}
		s.bytes -= int64(len(oldest.data))
		delete(s.m, victim)
	}
	s.tick++
	s.m[k] = &odbCacheEntry{typ: typ, data: data, tick: s.tick}
	s.bytes += sz
}
