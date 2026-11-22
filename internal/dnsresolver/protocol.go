package dnsresolver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const maxNameJumps = 128

type parsedAnswer struct {
	addrs     []netip.Addr
	cname     string
	cnameHops int
}

func validName(name string) error {
	if len(name) == 0 || len(name) > 253 {
		return errors.New("dnsresolver: invalid DNS name length")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("dnsresolver: invalid DNS label")
		}
	}
	return nil
}

func buildQuery(id uint16, name string) ([]byte, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	b := make([]byte, 12, 12+len(name)+17)
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], 0x0100)
	binary.BigEndian.PutUint16(b[4:6], 1)
	binary.BigEndian.PutUint16(b[10:12], 1)
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0, 0, 1, 0, 1)                          // root, A, IN
	b = append(b, 0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0) // root, OPT, UDP=4096, no DO, RDLEN=0
	return b, nil
}

func parseResponse(msg []byte, id uint16, question string) (parsedAnswer, bool, error) {
	var out parsedAnswer
	if len(msg) < 12 {
		return out, false, errors.New("dnsresolver: short DNS header")
	}
	if binary.BigEndian.Uint16(msg[:2]) != id {
		return out, true, nil
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 {
		return out, true, nil
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	if qd == 0 && flags&0x020f != 0 {
		// Some servers omit the question in error responses. The ID and the
		// source address are the only identity checks available.
		return out, false, responseError(flags)
	}
	if qd != 1 {
		return out, true, nil
	}
	off := 12
	qname, next, err := decodeName(msg, off)
	if err != nil {
		return out, false, err
	}
	off = next
	if off+4 > len(msg) {
		return out, false, errors.New("dnsresolver: truncated question")
	}
	qtype := binary.BigEndian.Uint16(msg[off : off+2])
	qclass := binary.BigEndian.Uint16(msg[off+2 : off+4])
	off += 4
	if !strings.EqualFold(strings.TrimSuffix(qname, "."), strings.TrimSuffix(question, ".")) || qtype != 1 || qclass != 1 {
		return out, true, nil
	}
	if flags&0x020f != 0 {
		return out, false, responseError(flags)
	}
	cnames := make(map[string]string)
	addresses := make(map[string][]netip.Addr)
	for i := 0; i < an; i++ {
		owner, n, err := decodeName(msg, off)
		if err != nil {
			return out, false, err
		}
		off = n
		if off+10 > len(msg) {
			return out, false, errors.New("dnsresolver: truncated resource record")
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		class := binary.BigEndian.Uint16(msg[off+2 : off+4])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		rdata := off + 10
		end := rdata + rdlen
		if end < rdata || end > len(msg) {
			return out, false, errors.New("dnsresolver: invalid RDATA length")
		}
		key := strings.ToLower(strings.TrimSuffix(owner, "."))
		if class == 1 && typ == 1 && rdlen == 4 {
			var a [4]byte
			copy(a[:], msg[rdata:end])
			addresses[key] = append(addresses[key], netip.AddrFrom4(a))
		}
		if class == 1 && typ == 5 {
			target, _, e := decodeNameLimited(msg, rdata, end)
			if e != nil {
				return out, false, e
			}
			cnames[key] = strings.ToLower(strings.TrimSuffix(target, "."))
		}
		off = end
	}
	cur := strings.ToLower(strings.TrimSuffix(question, "."))
	for {
		if a := addresses[cur]; len(a) > 0 {
			out.addrs = a
			return out, false, nil
		}
		target := cnames[cur]
		if target == "" {
			if out.cnameHops > 0 {
				out.cname = cur
			}
			return out, false, nil
		}
		out.cnameHops++
		if out.cnameHops > maxCNAMEs {
			return out, false, errors.New("dnsresolver: CNAME limit exceeded")
		}
		cur = target
	}
}

// responseError maps the TC bit and a non-zero RCODE to an error.
func responseError(flags uint16) error {
	if flags&0x0200 != 0 {
		return ErrTruncated
	}
	rcode := flags & 0x000f
	if rcode == 3 {
		return ErrNXDomain
	}
	return fmt.Errorf("dnsresolver: response code %d", rcode)
}

func decodeName(msg []byte, start int) (string, int, error) {
	return decodeNameLimited(msg, start, len(msg))
}
func decodeNameLimited(msg []byte, start, linearEnd int) (string, int, error) {
	if start < 0 || start >= len(msg) || linearEnd > len(msg) {
		return "", 0, errors.New("dnsresolver: name out of bounds")
	}
	labels := make([]string, 0, 4)
	pos := start
	next := -1
	jumps := 0
	expanded := 0
	for {
		if pos >= len(msg) {
			return "", 0, errors.New("dnsresolver: truncated name")
		}
		l := int(msg[pos])
		if l&0xc0 == 0xc0 {
			if pos+1 >= len(msg) || (next < 0 && pos+2 > linearEnd) {
				return "", 0, errors.New("dnsresolver: truncated compression pointer")
			}
			ptr := int(l&0x3f)<<8 | int(msg[pos+1])
			if ptr >= len(msg) {
				return "", 0, errors.New("dnsresolver: compression pointer out of bounds")
			}
			if next < 0 {
				next = pos + 2
			}
			jumps++
			if jumps > maxNameJumps {
				return "", 0, errors.New("dnsresolver: compression pointer loop")
			}
			pos = ptr
			continue
		}
		if l&0xc0 != 0 {
			return "", 0, errors.New("dnsresolver: invalid label type")
		}
		pos++
		if l == 0 {
			if next < 0 {
				next = pos
			}
			break
		}
		if l > 63 || pos+l > len(msg) || (next < 0 && pos+l > linearEnd) {
			return "", 0, errors.New("dnsresolver: invalid label length")
		}
		expanded += l + 1
		if expanded > 255 {
			return "", 0, errors.New("dnsresolver: expanded name too long")
		}
		labels = append(labels, string(msg[pos:pos+l]))
		pos += l
	}
	return strings.Join(labels, "."), next, nil
}
