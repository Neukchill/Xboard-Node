// Package sudoku implements the Sudoku proxy kernel for Xboard-Node.
// It runs as a native Go TCP proxy that completely bypasses sing-box/xray.
//
// Wire format (all bytes XOR-obfuscated with a UUID-derived key):
//
//	+--------+----------+------+--------+----------+
//	| VER(1) | UUID(36) |CMD(1)|ATYP(1) | ADDR+PORT|
//	+--------+----------+------+--------+----------+
//
//	VER  : 0x53 ('S')
//	CMD  : 0x01=TCP  0x03=UDP (UDP returns RepCmdUnsupported)
//	ATYP : 0x01=IPv4  0x03=Domain  0x04=IPv6
//	ADDR : [addr bytes][port(2) big-endian]
//
//	Server replies 1 byte: 0x00=ok  0x01=auth fail  0x02=cmd unsupported
package sudoku

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	Version = 0x53 // 'S'

	CmdTCP = 0x01
	CmdUDP = 0x03

	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04

	RepSuccess        = 0x00
	RepAuthFail       = 0x01
	RepCmdUnsupported = 0x02

	uuidLen = 36
)

// baseSudoku is a valid 9×9 sudoku used as the key-derivation seed.
var baseSudoku = [81]byte{
	5, 3, 4, 6, 7, 8, 9, 1, 2,
	6, 7, 2, 1, 9, 5, 3, 4, 8,
	1, 9, 8, 3, 4, 2, 5, 6, 7,
	8, 5, 9, 7, 6, 1, 4, 2, 3,
	4, 2, 6, 8, 5, 3, 7, 9, 1,
	7, 1, 3, 9, 2, 4, 8, 5, 6,
	9, 6, 1, 5, 3, 7, 2, 8, 4,
	2, 8, 7, 4, 1, 9, 6, 3, 5,
	3, 4, 5, 2, 8, 6, 1, 7, 9,
}

// DeriveKey derives a 256-byte XOR key from a UUID string.
//  1. SHA-256(uuid) → 32-byte seed
//  2. Fisher-Yates shuffle of baseSudoku using seed bytes
//  3. Expand to 256 bytes: key[i] = perm[i%81] ^ seed[i%32]
func DeriveKey(uuid string) [256]byte {
	seed := sha256.Sum256([]byte(uuid))

	perm := baseSudoku
	for i := 80; i > 0; i-- {
		j := int(seed[i%32]) % (i + 1)
		perm[i], perm[j] = perm[j], perm[i]
	}

	var key [256]byte
	for i := range key {
		key[i] = perm[i%81] ^ seed[i%32]
	}
	return key
}

// xorBuf XOR-obfuscates (or de-obfuscates) a slice in-place using the key.
// The key offset starts at keyPos so we can handle multi-chunk de-obfuscation
// on a stream without restarting from 0 each time.
func xorBuf(data []byte, key [256]byte, keyPos int) {
	for i, b := range data {
		data[i] = b ^ key[(keyPos+i)%256]
	}
}

// Address represents a parsed destination address.
type Address struct {
	Type byte
	Host string
	Port uint16
}

func (a *Address) String() string {
	return net.JoinHostPort(a.Host, fmt.Sprintf("%d", a.Port))
}

// ReadHandshake reads and validates the Sudoku client handshake from conn.
// It tries every UUID in validUUIDs to find a matching key.
//
// Returns matched uuid, command byte, destination address, and error.
func ReadHandshake(conn net.Conn, validUUIDs []string) (uuid string, cmd byte, addr *Address, err error) {
	// Fixed header: VER(1) + UUID(36) + CMD(1) + ATYP(1) = 39 bytes
	fixedHdr := make([]byte, 39)
	if _, err = io.ReadFull(conn, fixedHdr); err != nil {
		return
	}

	for _, uid := range validUUIDs {
		key := DeriveKey(uid)
		hdr := make([]byte, 39)
		copy(hdr, fixedHdr)
		xorBuf(hdr, key, 0)

		if hdr[0] != Version {
			continue
		}
		if string(hdr[1:37]) != uid {
			continue
		}
		// Matched
		uuid = uid
		cmd = hdr[37]
		atyp := hdr[38]

		// Key offset for addr portion starts at 39 (we already consumed 39 bytes)
		addr, err = readAddr(conn, atyp, key, 39)
		return
	}

	err = fmt.Errorf("sudoku: auth failed – no matching UUID")
	return
}

// readAddr reads the variable-length address after the fixed header.
// keyPos is the byte offset into the XOR key (to continue obfuscation stream).
func readAddr(conn net.Conn, atyp byte, key [256]byte, keyPos int) (*Address, error) {
	a := &Address{Type: atyp}

	switch atyp {
	case AtypIPv4:
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		xorBuf(buf, key, keyPos)
		a.Host = net.IP(buf[:4]).String()
		a.Port = binary.BigEndian.Uint16(buf[4:])

	case AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		xorBuf(lenBuf, key, keyPos)
		domainLen := int(lenBuf[0])
		keyPos++

		buf := make([]byte, domainLen+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		xorBuf(buf, key, keyPos)
		a.Host = string(buf[:domainLen])
		a.Port = binary.BigEndian.Uint16(buf[domainLen:])

	case AtypIPv6:
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		xorBuf(buf, key, keyPos)
		a.Host = net.IP(buf[:16]).String()
		a.Port = binary.BigEndian.Uint16(buf[16:])

	default:
		return nil, fmt.Errorf("sudoku: unknown ATYP 0x%02x", atyp)
	}

	return a, nil
}

// WriteHandshake writes an obfuscated client handshake to conn.
// Used by client implementations; included here for reference / testing.
func WriteHandshake(conn net.Conn, uuid string, cmd byte, dest *Address) error {
	key := DeriveKey(uuid)

	var addrBuf []byte
	switch dest.Type {
	case AtypIPv4:
		ip := net.ParseIP(dest.Host).To4()
		if ip == nil {
			return fmt.Errorf("sudoku: invalid IPv4 %q", dest.Host)
		}
		addrBuf = make([]byte, 6)
		copy(addrBuf, ip)
		binary.BigEndian.PutUint16(addrBuf[4:], dest.Port)

	case AtypDomain:
		domain := []byte(dest.Host)
		addrBuf = make([]byte, 1+len(domain)+2)
		addrBuf[0] = byte(len(domain))
		copy(addrBuf[1:], domain)
		binary.BigEndian.PutUint16(addrBuf[1+len(domain):], dest.Port)

	case AtypIPv6:
		ip := net.ParseIP(dest.Host).To16()
		if ip == nil {
			return fmt.Errorf("sudoku: invalid IPv6 %q", dest.Host)
		}
		addrBuf = make([]byte, 18)
		copy(addrBuf, ip)
		binary.BigEndian.PutUint16(addrBuf[16:], dest.Port)

	default:
		return fmt.Errorf("sudoku: unknown dest ATYP 0x%02x", dest.Type)
	}

	payload := make([]byte, 1+uuidLen+1+1+len(addrBuf))
	payload[0] = Version
	copy(payload[1:37], uuid)
	payload[37] = cmd
	payload[38] = dest.Type
	copy(payload[39:], addrBuf)

	xorBuf(payload, key, 0)
	_, err := conn.Write(payload)
	return err
}

// WriteReply sends a 1-byte reply to the client. Not obfuscated.
func WriteReply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{rep})
	return err
}
