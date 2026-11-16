package ctstream

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var errMalformedWire = errors.New("ctstream: malformed wire data")

const (
	entryX509    = uint16(0)
	entryPrecert = uint16(1)
)

type wireReader struct {
	b   []byte
	off int
}

func (r *wireReader) take(n int) ([]byte, bool) {
	if n < 0 || n > len(r.b)-r.off {
		return nil, false
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v, true
}

func (r *wireReader) u16() (uint16, bool) {
	b, ok := r.take(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(b), true
}

func (r *wireReader) vector16() ([]byte, bool) {
	n, ok := r.u16()
	if !ok {
		return nil, false
	}
	return r.take(int(n))
}

func (r *wireReader) vector24() ([]byte, bool) {
	b, ok := r.take(3)
	if !ok {
		return nil, false
	}
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	return r.take(n)
}

// parseLeafInput parses an RFC 6962 MerkleTreeLeaf and returns only the
// certificate material needed by internal/domain. extra_data (the chain) is
// deliberately not parsed.
func parseLeafInput(data []byte) (der []byte, isTBS bool, err error) {
	r := wireReader{b: data}
	header, ok := r.take(10) // version, leaf type, timestamp
	if !ok || header[0] != 0 || header[1] != 0 {
		return nil, false, errMalformedWire
	}
	typ, ok := r.u16()
	if !ok {
		return nil, false, errMalformedWire
	}
	switch typ {
	case entryX509:
		der, ok = r.vector24()
	case entryPrecert:
		if _, ok = r.take(32); ok {
			der, ok = r.vector24()
		}
		isTBS = true
	default:
		return nil, false, errMalformedWire
	}
	if !ok {
		return nil, false, errMalformedWire
	}
	if _, ok = r.vector16(); !ok || r.off != len(data) || len(der) == 0 {
		return nil, false, errMalformedWire
	}
	return append([]byte(nil), der...), isTBS, nil
}

// parseTileData parses a Static CT data tile. It validates every TLS vector,
// skips extensions, submitted precert data and chain fingerprints, and copies
// only certificate/TBSCertificate DER into a bounded result.
func parseTileData(data []byte, maxEntries int) ([]tileEntry, error) {
	if maxEntries <= 0 || maxEntries > tileWidth {
		return nil, errMalformedWire
	}
	r := wireReader{b: data}
	out := make([]tileEntry, 0, maxEntries)
	for r.off < len(data) {
		if len(out) == maxEntries {
			return nil, errMalformedWire
		}
		if _, ok := r.take(8); !ok { // timestamp
			return nil, errMalformedWire
		}
		typ, ok := r.u16()
		if !ok {
			return nil, errMalformedWire
		}
		var der []byte
		var tbs bool
		switch typ {
		case entryX509:
			der, ok = r.vector24()
			if ok {
				_, ok = r.vector16() // extensions
			}
			if ok {
				_, ok = r.vector16() // chain fingerprints
			}
		case entryPrecert:
			tbs = true
			if _, ok = r.take(32); ok {
				der, ok = r.vector24() // defanged TBS
			}
			if ok {
				_, ok = r.vector16() // extensions
			}
			if ok {
				_, ok = r.vector24() // submitted precertificate; not needed
			}
			if ok {
				_, ok = r.vector16() // chain fingerprints
			}
		default:
			return nil, fmt.Errorf("%w: entry type %d", errMalformedWire, typ)
		}
		if !ok || len(der) == 0 {
			return nil, errMalformedWire
		}
		out = append(out, tileEntry{der: append([]byte(nil), der...), isTBS: tbs})
	}
	if len(out) != maxEntries {
		return nil, errMalformedWire
	}
	return out, nil
}

type tileEntry struct {
	der   []byte
	isTBS bool
}
