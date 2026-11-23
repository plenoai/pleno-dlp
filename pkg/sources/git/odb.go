package git

import (
	"bytes"
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
	"sync/atomic"

	kzlib "github.com/klauspost/compress/zlib"
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
	packs []*odbPack
	cache *odbCache
	bufs  odbBufPool
	zr    sync.Pool // *odbInflater
	work  sync.Pool // *odbWork
}

// openObjectDB maps every pack under objectsDir and its alternates. It
// returns nil when nothing can be read in process.
func openObjectDB(objectsDir string, cacheBytes int64) (*objectDB, error) {
	db := &objectDB{}
	db.cache = newODBCache(db, cacheBytes)
	db.zr.New = func() any { return &odbInflater{} }
	db.work.New = func() any { return &odbWork{} }
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

// readBlobRef returns the blob's content zero-copy: the caller reads
// ref.data and must call ref.release(db) when done.
func (db *objectDB) readBlobRef(oid string, limit int64) (*odbBuf, error) {
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
		typ, ref, err := db.object(pi, off, limit)
		if err != nil {
			return nil, err
		}
		if typ != odbObjBlob {
			ref.release(db)
			return nil, errODBMiss
		}
		return ref, nil
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

// odbMaxChain bounds a delta chain; git itself writes at most depth 4095.
const odbMaxChain = 4096

// odbLink is one delta of a chain being resolved.
type odbLink struct {
	off  int64 // the delta object's offset (its cache key)
	pos  int64 // start of its compressed delta data
	size int64 // inflated delta size
}

// odbWork is per-call scratch, pooled so steady-state reads allocate
// nothing: the chain stack and the inflated delta instructions.
type odbWork struct {
	chain []odbLink
	delta []byte
}

// object reconstructs the object at off and returns it with a reference
// the caller must release. Every level of a delta chain, the result
// included, lands in the shared cache in a recycled buffer: history walks
// read each blob version twice (as one commit's new side and an older
// commit's old side) and every version is the base of the next older one,
// so caching the result turns most reads into a hit or one delta.
func (db *objectDB) object(pi int, off int64, limit int64) (int, *odbBuf, error) {
	if typ, ref, ok := db.cache.get(pi, off); ok {
		if int64(len(ref.data)) > limit {
			ref.release(db)
			return typ, nil, errODBMiss
		}
		return typ, ref, nil
	}
	w := db.work.Get().(*odbWork)
	defer db.work.Put(w)
	p := db.packs[pi]
	chain := w.chain[:0]
	defer func() { w.chain = chain[:0] }()
	cur := off
	var (
		baseTyp int
		base    *odbBuf // owned reference to the chain's resolved bottom
	)
	for {
		if len(chain) > 0 {
			if typ, ref, ok := db.cache.get(pi, cur); ok {
				baseTyp, base = typ, ref
				break
			}
		}
		typ, size, pos, err := p.header(cur)
		if err != nil {
			return 0, nil, err
		}
		if typ == odbObjCommit || typ == odbObjTree || typ == odbObjBlob || typ == odbObjTag {
			if (len(chain) == 0 && size > limit) || size > 1<<31 {
				return typ, nil, errODBMiss
			}
			b := db.bufs.get(size)
			data, err := db.inflate(p, pos, size, b.data[:0])
			if err != nil {
				b.release(db)
				return 0, nil, err
			}
			b.data = data
			db.cache.put(pi, cur, typ, b)
			baseTyp, base = typ, b
			break
		}
		if typ != odbObjOfsDelta && typ != odbObjRefDelta || len(chain) >= odbMaxChain || size > 1<<31 {
			return 0, nil, errODBMiss
		}
		next, dpos, err := p.deltaBase(cur, typ, pos)
		if err != nil {
			return 0, nil, err
		}
		chain = append(chain, odbLink{off: cur, pos: dpos, size: size})
		cur = next
	}
	for i := len(chain) - 1; i >= 0; i-- {
		l := chain[i]
		delta, err := db.inflate(p, l.pos, l.size, w.delta[:0])
		if err != nil {
			base.release(db)
			return 0, nil, err
		}
		w.delta = delta
		srcSize, n, ok := deltaVarint(delta, 0)
		if !ok || srcSize != int64(len(base.data)) {
			base.release(db)
			return 0, nil, errODBMiss
		}
		dstSize, _, ok := deltaVarint(delta, n)
		if !ok || dstSize > 1<<31 || (i == 0 && dstSize > limit) {
			base.release(db)
			return 0, nil, errODBMiss
		}
		nb := db.bufs.get(dstSize)
		out, err := applyDelta(base.data, delta, dstSize, nb.data[:0])
		base.release(db)
		if err != nil {
			nb.release(db)
			return 0, nil, err
		}
		nb.data = out
		db.cache.put(pi, l.off, baseTyp, nb)
		base = nb
	}
	return baseTyp, base, nil
}

// deltaBase decodes the base reference of the delta object at off whose
// header ends at pos; it returns the base's offset and the delta data start.
func (p *odbPack) deltaBase(off int64, typ int, pos int64) (int64, int64, error) {
	b := p.pack
	if typ == odbObjOfsDelta {
		if pos >= int64(len(b)) {
			return 0, 0, errODBMiss
		}
		c := b[pos]
		pos++
		rel := int64(c & 0x7f)
		for c&0x80 != 0 {
			if pos >= int64(len(b)) || rel > 1<<55 {
				return 0, 0, errODBMiss
			}
			c = b[pos]
			pos++
			rel = ((rel + 1) << 7) | int64(c&0x7f)
		}
		if rel <= 0 || rel > off {
			return 0, 0, errODBMiss
		}
		return off - rel, pos, nil
	}
	if pos+20 > int64(len(b)) {
		return 0, 0, errODBMiss
	}
	baseOff, ok := p.find(b[pos : pos+20])
	if !ok {
		// Thin packs never reach a repository; other packs are out of scope.
		return 0, 0, errODBMiss
	}
	return baseOff, pos + 20, nil
}

// growBuf returns dst resized to n, reusing its storage when it fits.
func growBuf(dst []byte, n int64) []byte {
	if dst != nil && int64(cap(dst)) >= n {
		return dst[:n]
	}
	return make([]byte, n)
}

// inflate decompresses size bytes of the zlib stream at pos into dst's
// storage. klauspost's decoder takes a byte-slice fast path for
// *bytes.Reader, roughly halving inflate CPU against compress/flate.
func (db *objectDB) inflate(p *odbPack, pos, size int64, dst []byte) ([]byte, error) {
	if pos >= int64(len(p.pack)) {
		return nil, errODBMiss
	}
	z := db.zr.Get().(*odbInflater)
	defer db.zr.Put(z)
	z.src.Reset(p.pack[pos:])
	if z.r == nil {
		r, err := kzlib.NewReader(&z.src)
		if err != nil {
			return nil, errODBMiss
		}
		z.r = r
	} else if err := z.r.(kzlib.Resetter).Reset(&z.src, nil); err != nil {
		return nil, errODBMiss
	}
	out := growBuf(dst, size)
	if _, err := io.ReadFull(z.r, out); err != nil {
		return nil, errODBMiss
	}
	return out, nil
}

type odbInflater struct {
	src bytes.Reader
	r   io.ReadCloser
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

// odbBuf is a reference-counted buffer recycled through odbBufPool. The
// cache holds one reference while an entry is resident and every reader
// holds one while it uses the data, so eviction never frees memory a
// concurrent delta application is still reading.
type odbBuf struct {
	data []byte
	refs atomic.Int32
}

func (b *odbBuf) release(db *objectDB) {
	if b.refs.Add(-1) == 0 {
		db.bufs.put(b)
	}
}

// odbBufPool recycles buffers by power-of-two capacity class. Reusing the
// same few hundred MiB keeps the reader from re-zeroing fresh spans and
// from page-committing new heap on every reconstructed base (#1019).
type odbBufPool struct {
	classes [odbBufClasses]odbBufClass
}

const (
	odbBufMinShift = 10 // 1 KiB
	odbBufClasses  = 22 // up to 2 GiB
	// odbBufFreeLimit bounds the idle bytes kept per class.
	odbBufFreeLimit = 32 << 20
)

type odbBufClass struct {
	mu    sync.Mutex
	free  []*odbBuf
	bytes int64
}

func odbBufClassOf(n int64) int {
	c := 0
	for int64(1)<<(c+odbBufMinShift) < n {
		c++
	}
	return c
}

// get returns a buffer with capacity for n bytes and one reference.
func (p *odbBufPool) get(n int64) *odbBuf {
	c := odbBufClassOf(n)
	if c < odbBufClasses {
		cl := &p.classes[c]
		cl.mu.Lock()
		if k := len(cl.free); k > 0 {
			b := cl.free[k-1]
			cl.free = cl.free[:k-1]
			cl.bytes -= int64(cap(b.data))
			cl.mu.Unlock()
			b.data = b.data[:0]
			b.refs.Store(1)
			return b
		}
		cl.mu.Unlock()
	}
	capacity := n
	if c < odbBufClasses {
		capacity = int64(1) << (c + odbBufMinShift)
	}
	b := &odbBuf{data: make([]byte, 0, capacity)}
	b.refs.Store(1)
	return b
}

func (p *odbBufPool) put(b *odbBuf) {
	c := odbBufClassOf(int64(cap(b.data)))
	if c >= odbBufClasses || int64(1)<<(c+odbBufMinShift) != int64(cap(b.data)) {
		return
	}
	cl := &p.classes[c]
	cl.mu.Lock()
	if cl.bytes+int64(cap(b.data)) <= odbBufFreeLimit {
		cl.free = append(cl.free, b)
		cl.bytes += int64(cap(b.data))
	}
	cl.mu.Unlock()
}

// odbCache is the walk's one bounded delta-base cache, shared by every
// renderer: lock-striped by offset, exact LRU within each stripe.
type odbCache struct {
	shards [64]odbCacheShard
}

type odbCacheKey struct {
	pack int
	off  int64
}

type odbCacheEntry struct {
	key        odbCacheKey
	typ        int
	buf        *odbBuf
	prev, next *odbCacheEntry
}

type odbCacheShard struct {
	mu    sync.Mutex
	m     map[odbCacheKey]*odbCacheEntry
	head  odbCacheEntry // sentinel: head.next is most recent
	bytes int64
	limit int64
	db    *objectDB
}

func newODBCache(db *objectDB, total int64) *odbCache {
	c := &odbCache{}
	for i := range c.shards {
		s := &c.shards[i]
		s.m = make(map[odbCacheKey]*odbCacheEntry)
		s.limit = total / int64(len(c.shards))
		s.head.prev, s.head.next = &s.head, &s.head
		s.db = db
	}
	return c
}

func (c *odbCache) shard(off int64) *odbCacheShard {
	return &c.shards[(uint64(off)*0x9e3779b97f4a7c15)>>58]
}

func (s *odbCacheShard) unlink(e *odbCacheEntry) {
	e.prev.next, e.next.prev = e.next, e.prev
}

func (s *odbCacheShard) pushFront(e *odbCacheEntry) {
	e.prev, e.next = &s.head, s.head.next
	s.head.next.prev = e
	s.head.next = e
}

// get returns the cached object with a reference the caller must release.
func (c *odbCache) get(pack int, off int64) (int, *odbBuf, bool) {
	s := c.shard(off)
	s.mu.Lock()
	e, ok := s.m[odbCacheKey{pack, off}]
	if !ok {
		s.mu.Unlock()
		return 0, nil, false
	}
	s.unlink(e)
	s.pushFront(e)
	e.buf.refs.Add(1)
	s.mu.Unlock()
	return e.typ, e.buf, true
}

// put caches buf under (pack, off), taking a reference of its own.
func (c *odbCache) put(pack int, off int64, typ int, buf *odbBuf) {
	s := c.shard(off)
	sz := int64(cap(buf.data))
	if sz > s.limit/4 {
		return
	}
	k := odbCacheKey{pack, off}
	var evicted []*odbBuf
	s.mu.Lock()
	if _, ok := s.m[k]; ok {
		s.mu.Unlock()
		return
	}
	for s.bytes+sz > s.limit && s.head.prev != &s.head {
		v := s.head.prev
		s.unlink(v)
		delete(s.m, v.key)
		s.bytes -= int64(cap(v.buf.data))
		evicted = append(evicted, v.buf)
	}
	buf.refs.Add(1)
	e := &odbCacheEntry{key: k, typ: typ, buf: buf}
	s.m[k] = e
	s.pushFront(e)
	s.bytes += sz
	s.mu.Unlock()
	for _, b := range evicted {
		b.release(s.db)
	}
}
