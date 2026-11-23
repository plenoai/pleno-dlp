package archive

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// A read-only, pure-Go SQLite file-format reader. It walks table b-trees
// from sqlite_schema and renders every row as an INSERT statement with
// column names, so keyword-anchored detectors see "api_key" next to the
// value. Nothing is executed; the file is parsed as bytes.
// Format reference: https://www.sqlite.org/fileformat2.html

var sqliteMagic = []byte("SQLite format 3\x00")

const (
	sqliteMaxBinaryBlob = 4 << 10
	sqliteMaxTables     = 4096
)

type sqliteTable struct {
	name    string
	root    uint32
	columns []string
	ipk     int // column index aliasing rowid, or -1
}

type sqliteDB struct {
	data     []byte
	pageSize int
	usable   int
	pages    uint32
	encoding uint32
	visited  map[uint32]bool
	budget   int // remaining page visits for this file
}

func openSQLite(data []byte) (*sqliteDB, error) {
	if len(data) < 100 || !bytes.HasPrefix(data, sqliteMagic) {
		return nil, errors.New("not a SQLite database")
	}
	pageSize := int(binary.BigEndian.Uint16(data[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("invalid page size %d", pageSize)
	}
	reserved := int(data[20])
	usable := pageSize - reserved
	if usable < 480 {
		return nil, fmt.Errorf("invalid usable page size %d", usable)
	}
	pages := uint32(len(data) / pageSize)
	encoding := binary.BigEndian.Uint32(data[56:60])
	return &sqliteDB{data: data, pageSize: pageSize, usable: usable, pages: pages, encoding: encoding, budget: int(pages) * 2}, nil
}

func (db *sqliteDB) page(n uint32) ([]byte, int, error) {
	if n == 0 || n > db.pages {
		return nil, 0, fmt.Errorf("page %d out of range", n)
	}
	if db.budget <= 0 {
		return nil, 0, errors.New("page visit budget exhausted")
	}
	db.budget--
	start := int(n-1) * db.pageSize
	header := 0
	if n == 1 {
		header = 100
	}
	return db.data[start : start+db.pageSize], header, nil
}

func sqliteVarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}

// payload returns the full record payload of a table-leaf cell, following
// overflow pages.
func (db *sqliteDB) payload(pg []byte, off int) (rowid int64, body []byte, err error) {
	if off >= len(pg) {
		return 0, nil, errors.New("cell offset out of range")
	}
	size, n := sqliteVarint(pg[off:])
	if n == 0 {
		return 0, nil, errors.New("truncated payload size")
	}
	off += n
	rid, n := sqliteVarint(pg[off:])
	if n == 0 {
		return 0, nil, errors.New("truncated rowid")
	}
	off += n
	if size > uint64(len(db.data)) {
		return 0, nil, fmt.Errorf("payload size %d exceeds file", size)
	}
	p := int(size)
	u := db.usable
	x := u - 35
	local := p
	if p > x {
		m := ((u-12)*32/255 - 23)
		k := m + (p-m)%(u-4)
		if k <= x {
			local = k
		} else {
			local = m
		}
	}
	if off+local > len(pg) {
		return 0, nil, errors.New("local payload out of range")
	}
	body = make([]byte, 0, p)
	body = append(body, pg[off:off+local]...)
	if local == p {
		return int64(rid), body, nil
	}
	if off+local+4 > len(pg) {
		return 0, nil, errors.New("overflow pointer out of range")
	}
	next := binary.BigEndian.Uint32(pg[off+local:])
	seen := map[uint32]bool{}
	for len(body) < p {
		if next == 0 || seen[next] {
			return 0, nil, errors.New("broken overflow chain")
		}
		seen[next] = true
		op, _, err := db.page(next)
		if err != nil {
			return 0, nil, err
		}
		next = binary.BigEndian.Uint32(op[:4])
		take := min(p-len(body), u-4)
		body = append(body, op[4:4+take]...)
	}
	return int64(rid), body, nil
}

type sqliteValue struct {
	kind byte // 'n' null, 'i' int, 'f' float, 't' text, 'b' blob
	i    int64
	f    float64
	b    []byte
}

func (db *sqliteDB) record(body []byte) ([]sqliteValue, error) {
	hlen, n := sqliteVarint(body)
	if n == 0 || hlen > uint64(len(body)) || int(hlen) < n {
		return nil, errors.New("invalid record header")
	}
	hdr := body[n:hlen]
	data := body[hlen:]
	var values []sqliteValue
	for len(hdr) > 0 {
		st, k := sqliteVarint(hdr)
		if k == 0 {
			return nil, errors.New("truncated serial type")
		}
		hdr = hdr[k:]
		var size int
		switch {
		case st == 0, st == 8, st == 9:
		case st >= 1 && st <= 4:
			size = int(st)
		case st == 5:
			size = 6
		case st == 6, st == 7:
			size = 8
		case st >= 12:
			size = int((st - 12) / 2)
		default:
			return nil, fmt.Errorf("reserved serial type %d", st)
		}
		if size > len(data) {
			return nil, errors.New("record value out of range")
		}
		raw := data[:size]
		data = data[size:]
		v := sqliteValue{kind: 'n'}
		switch {
		case st == 8:
			v = sqliteValue{kind: 'i'}
		case st == 9:
			v = sqliteValue{kind: 'i', i: 1}
		case st >= 1 && st <= 6:
			var x int64
			for _, c := range raw {
				x = x<<8 | int64(c)
			}
			shift := 64 - 8*uint(size)
			v = sqliteValue{kind: 'i', i: x << shift >> shift}
		case st == 7:
			v = sqliteValue{kind: 'f', f: math.Float64frombits(binary.BigEndian.Uint64(raw))}
		case st >= 12 && st%2 == 0:
			v = sqliteValue{kind: 'b', b: raw}
		case st >= 13:
			v = sqliteValue{kind: 't', b: db.text(raw)}
		}
		values = append(values, v)
	}
	return values, nil
}

func (db *sqliteDB) text(raw []byte) []byte {
	if db.encoding != 2 && db.encoding != 3 {
		return raw
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		if db.encoding == 2 {
			units[i] = binary.LittleEndian.Uint16(raw[2*i:])
		} else {
			units[i] = binary.BigEndian.Uint16(raw[2*i:])
		}
	}
	return []byte(string(utf16.Decode(units)))
}

// walkTable visits every row of the table b-tree rooted at root.
func (db *sqliteDB) walkTable(root uint32, visit func(int64, []sqliteValue) bool) error {
	stack := []uint32{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if db.visited[n] {
			return fmt.Errorf("b-tree page %d revisited", n)
		}
		db.visited[n] = true
		pg, h, err := db.page(n)
		if err != nil {
			return err
		}
		if h+8 > len(pg) {
			return errors.New("page header out of range")
		}
		kind := pg[h]
		cells := int(binary.BigEndian.Uint16(pg[h+3:]))
		ptrs := h + 8
		switch kind {
		case 0x05:
			ptrs = h + 12
			if ptrs > len(pg) {
				return errors.New("page header out of range")
			}
			right := binary.BigEndian.Uint32(pg[h+8:])
			children := []uint32{right}
			for i := cells - 1; i >= 0; i-- {
				p := ptrs + 2*i
				if p+2 > len(pg) {
					return errors.New("cell pointer out of range")
				}
				off := int(binary.BigEndian.Uint16(pg[p:]))
				if off+4 > len(pg) {
					return errors.New("cell out of range")
				}
				children = append(children, binary.BigEndian.Uint32(pg[off:]))
			}
			// Push right-most first so rows come out in key order.
			stack = append(stack, children...)
		case 0x0d:
			for i := 0; i < cells; i++ {
				p := ptrs + 2*i
				if p+2 > len(pg) {
					return errors.New("cell pointer out of range")
				}
				rowid, body, err := db.payload(pg, int(binary.BigEndian.Uint16(pg[p:])))
				if err != nil {
					return err
				}
				values, err := db.record(body)
				if err != nil {
					return err
				}
				if !visit(rowid, values) {
					return nil
				}
			}
		default:
			// Index and WITHOUT ROWID b-trees are not row tables.
			return fmt.Errorf("unsupported b-tree page type 0x%02x", kind)
		}
	}
	return nil
}

// sqliteColumns parses column names from a CREATE TABLE statement.
func sqliteColumns(sql string) (columns []string, ipk int) {
	ipk = -1
	open := strings.IndexByte(sql, '(')
	closeIdx := strings.LastIndexByte(sql, ')')
	if open < 0 || closeIdx <= open {
		return nil, ipk
	}
	body := sql[open+1 : closeIdx]
	var parts []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case quote != 0:
			if c == quote || (quote == '[' && c == ']') {
				quote = 0
			}
		case c == '"' || c == '\'' || c == '`' || c == '[':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 0:
			parts = append(parts, body[start:i])
			start = i + 1
		}
	}
	parts = append(parts, body[start:])
	for _, part := range parts {
		part = strings.TrimSpace(part)
		upper := strings.ToUpper(part)
		if part == "" || strings.HasPrefix(upper, "CONSTRAINT") || strings.HasPrefix(upper, "PRIMARY KEY") ||
			strings.HasPrefix(upper, "UNIQUE") || strings.HasPrefix(upper, "CHECK") || strings.HasPrefix(upper, "FOREIGN KEY") {
			continue
		}
		name := part
		switch part[0] {
		case '"', '`', '[':
			endQuote := part[0]
			if endQuote == '[' {
				endQuote = ']'
			}
			if j := strings.IndexByte(part[1:], endQuote); j >= 0 {
				name = part[1 : j+1]
			}
		default:
			if j := strings.IndexAny(part, " \t\r\n"); j >= 0 {
				name = part[:j]
			}
		}
		if strings.Contains(strings.Join(strings.Fields(upper), " "), "INTEGER PRIMARY KEY") {
			ipk = len(columns)
		}
		columns = append(columns, name)
	}
	return columns, ipk
}

func sqliteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func writeSQLiteValue(out *textBuffer, v sqliteValue) bool {
	switch v.kind {
	case 'i':
		return out.writeString(strconv.FormatInt(v.i, 10))
	case 'f':
		return out.writeString(strconv.FormatFloat(v.f, 'g', -1, 64))
	case 't':
		return out.writeString("'" + strings.ReplaceAll(string(v.b), "'", "''") + "'")
	case 'b':
		if utf8.Valid(v.b) && !bytes.ContainsRune(v.b, 0) {
			return out.writeString("'" + strings.ReplaceAll(string(v.b), "'", "''") + "'")
		}
		if len(v.b) > sqliteMaxBinaryBlob {
			return out.writeString(fmt.Sprintf("X'<%d bytes>'", len(v.b)))
		}
		return out.writeString("X'" + hex.EncodeToString(v.b) + "'")
	}
	return out.writeString("NULL")
}

// sqliteTables reads table definitions from sqlite_schema (rooted at page 1).
func (db *sqliteDB) tables() ([]sqliteTable, error) {
	var tables []sqliteTable
	err := db.walkTable(1, func(_ int64, v []sqliteValue) bool {
		if len(v) < 5 || v[0].kind != 't' || string(v[0].b) != "table" || v[3].kind != 'i' || v[3].i <= 0 {
			return true
		}
		t := sqliteTable{name: string(v[1].b), root: uint32(v[3].i), ipk: -1}
		if v[4].kind == 't' {
			t.columns, t.ipk = sqliteColumns(string(v[4].b))
		}
		tables = append(tables, t)
		return len(tables) < sqliteMaxTables
	})
	return tables, err
}

// extractSQLite renders every row-table as CREATE/INSERT text. Per-table
// failures are reported but do not stop other tables.
func extractSQLite(data []byte, out *textBuffer) error {
	db, err := openSQLite(data)
	if err != nil {
		return err
	}
	db.visited = map[uint32]bool{}
	tables, err := db.tables()
	if err != nil && len(tables) == 0 {
		return err
	}
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	for _, t := range tables {
		header := "INSERT INTO " + sqliteIdent(t.name) + " ("
		for i, c := range t.columns {
			if i > 0 {
				header += ", "
			}
			header += sqliteIdent(c)
		}
		header += ") VALUES ("
		werr := db.walkTable(t.root, func(rowid int64, values []sqliteValue) bool {
			if !out.writeString(header) {
				return false
			}
			for i, v := range values {
				if i > 0 && !out.writeString(", ") {
					return false
				}
				if i == t.ipk && v.kind == 'n' {
					v = sqliteValue{kind: 'i', i: rowid}
				}
				if !writeSQLiteValue(out, v) {
					return false
				}
			}
			return out.writeString(");\n")
		})
		if werr != nil {
			errs = append(errs, fmt.Errorf("table %q: %w", t.name, werr))
		}
		if out.overflow {
			break
		}
	}
	return errors.Join(errs...)
}
