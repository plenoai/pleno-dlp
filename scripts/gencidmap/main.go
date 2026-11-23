// Command gencidmap regenerates pkg/archive/cidmaps from Adobe's
// cmap-resources (BSD-3-Clause) at a pinned commit:
//
//	go run ./scripts/gencidmap -out pkg/archive/cidmaps
//
// For each registered character collection it reads cid2code.txt, which
// lists every CID with its code in each CMap, takes the UTF-32 Unicode
// columns (including JIS2004/X0213 forms and vertical "v" entries, so
// variant CIDs such as Japan1 20282 for U+6756 decode too), picks one code
// point per CID (see rank), and writes runs of consecutive CIDs with
// consecutive code points as uvarints:
//
//	cidDelta (from the previous run's end), codePoint, runLength
//
// compressed with raw DEFLATE at best compression. Downloads are verified
// against pinned SHA-256 digests so the output is reproducible.
package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	upstream = "https://raw.githubusercontent.com/adobe-type-tools/cmap-resources"
	commit   = "f5cf3bca7fdfeaceb77aa82847e974f2306c20b4" // 2023-11-15
)

type collection struct {
	ordering string
	file     string
}

var collections = []collection{
	{"Japan1", "Adobe-Japan1-7/cid2code.txt"},
	{"GB1", "Adobe-GB1-6/cid2code.txt"},
	{"CNS1", "Adobe-CNS1-7/cid2code.txt"},
	{"Korea1", "Adobe-Korea1-2/cid2code.txt"},
	{"KR", "Adobe-KR-9/cid2code.txt"},
}

// digests pins each upstream file; regenerate with -print-digests after
// bumping commit.
var digests = map[string]string{
	"Adobe-Japan1-7/cid2code.txt": "5c4bc3adfecc348e67c36c8572d247b1ab3b42f281c6aedddf82bcf1db847a00",
	"Adobe-GB1-6/cid2code.txt":    "ed89f0b27bec2d7772ba9f2b757f0d0a6b9af34966bd9f230caf271d5dcbf2f0",
	"Adobe-CNS1-7/cid2code.txt":   "fc4bb918f90dfec5a94412cc1b83e87123878ce78af1488e9127650ccdf943be",
	"Adobe-Korea1-2/cid2code.txt": "593325fb20bb6b928b203ff3eb2531821069301b440814effbca9d556c2e96e8",
	"Adobe-KR-9/cid2code.txt":     "4f803898bfb040f2d1d2ae589e76929b3305a4f89ce3ada53847ef18a24c1e11",
}

func main() {
	out := flag.String("out", "pkg/archive/cidmaps", "output directory")
	printDigests := flag.Bool("print-digests", false, "print upstream SHA-256 digests instead of verifying them")
	flag.Parse()
	client := &http.Client{Timeout: time.Minute}
	for _, c := range collections {
		body := fetch(client, c.file)
		sum := sha256.Sum256(body)
		got := hex.EncodeToString(sum[:])
		if *printDigests {
			fmt.Printf("\t%q: %q,\n", c.file, got)
			continue
		} else if want := digests[c.file]; want != got {
			log.Fatalf("%s: sha256 %s, want %s", c.file, got, want)
		}
		table := parse(body)
		if *printDigests {
			continue
		}
		data := encode(table)
		path := filepath.Join(*out, c.ordering+".bin")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			log.Fatal(err)
		}
		log.Printf("%s: %d CIDs, %d bytes", c.ordering, len(table), len(data))
	}
	if !*printDigests {
		lic := fetch(client, "LICENSE.md")
		if err := os.WriteFile(filepath.Join(*out, "LICENSE.md"), lic, 0o644); err != nil {
			log.Fatal(err)
		}
	}
}

func fetch(client *http.Client, path string) []byte {
	resp, err := client.Get(upstream + "/" + commit + "/" + path)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("%s: %s", path, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		log.Fatal(err)
	}
	return body
}

func privateUse(cp uint32) bool {
	return (cp >= 0xE000 && cp <= 0xF8FF) || cp >= 0xF0000
}

// rank orders candidate code points for one CID: CJK radicals (Kangxi and
// supplement) and compatibility ideographs lose to any other code point, so CID 1200 decodes as U+65E5 rather than KANGXI RADICAL SUN
// U+2F47; ties go to the smaller code point.
func rank(cp uint32) uint64 {
	penalized := (cp >= 0x2E80 && cp <= 0x2FDF) ||
		(cp >= 0xF900 && cp <= 0xFAFF) ||
		(cp >= 0x2F800 && cp <= 0x2FA1F)
	if penalized {
		return 1<<32 | uint64(cp)
	}
	return uint64(cp)
}

// parse reads cid2code.txt: a tab-separated table whose header row starts
// with "CID"; Unicode cells are comma-separated hex code points, a "v"
// suffix marking a vertical form, and "*" for none.
func parse(body []byte) map[uint32]uint32 {
	table := map[uint32]uint32{}
	var cols []int
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Split(line, "	")
		if fields[0] == "CID" {
			for i, h := range fields {
				if strings.Contains(h, "UTF32") {
					cols = append(cols, i)
				}
			}
			continue
		}
		cid, err := strconv.ParseUint(fields[0], 10, 16)
		if err != nil || len(cols) == 0 {
			log.Fatalf("bad cid2code row %q", line)
		}
		best, found := uint32(0), false
		for _, i := range cols {
			if i >= len(fields) || strings.TrimSpace(fields[i]) == "*" || strings.TrimSpace(fields[i]) == "" {
				continue
			}
			for _, v := range strings.Split(fields[i], ",") {
				cp, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), "v"), 16, 32)
				if err != nil {
					log.Fatalf("bad code %q for CID %d", v, cid)
				}
				if privateUse(uint32(cp)) {
					continue // vendor (e.g. HKSCS) code points carry no portable text
				}
				if !found || rank(uint32(cp)) < rank(best) {
					best, found = uint32(cp), true
				}
			}
		}
		if found {
			table[uint32(cid)] = best
		}
	}
	if len(cols) == 0 {
		log.Fatal("cid2code.txt has no UTF32 column")
	}
	return table
}

func encode(table map[uint32]uint32) []byte {
	cids := make([]uint32, 0, len(table))
	for cid := range table {
		cids = append(cids, cid)
	}
	sort.Slice(cids, func(i, j int) bool { return cids[i] < cids[j] })
	var raw []byte
	next := uint32(0)
	for i := 0; i < len(cids); {
		j := i + 1
		for j < len(cids) && cids[j] == cids[j-1]+1 && table[cids[j]] == table[cids[j-1]]+1 {
			j++
		}
		raw = binary.AppendUvarint(raw, uint64(cids[i]-next))
		raw = binary.AppendUvarint(raw, uint64(table[cids[i]]))
		raw = binary.AppendUvarint(raw, uint64(j-i))
		next = cids[j-1] + 1
		i = j
	}
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write(raw)
	_ = w.Close()
	return buf.Bytes()
}
