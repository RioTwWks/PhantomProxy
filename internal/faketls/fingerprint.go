package faketls

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const (
	extSupportedGroups   uint16 = 0x000a
	extECPointFormats    uint16 = 0x000b
	extSignatureAlgs     uint16 = 0x000d
	extALPN              uint16 = 0x0010
	extSupportedVersions uint16 = 0x002b
	extPSKModes          uint16 = 0x002d
	extKeyShare          uint16 = 0x0033
)

// JA3 вычисляет JA3-отпечаток TLS ClientHello.
func JA3(record []byte) string {
	if len(record) < 5 {
		return ""
	}
	payload := record[5:]
	if len(payload) < 4 || payload[0] != 0x01 {
		return ""
	}

	helloLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	hello := payload[4:]
	if len(hello) < helloLen {
		return ""
	}
	hello = hello[:helloLen]
	if len(hello) < 34 {
		return ""
	}

	version := binary.BigEndian.Uint16(hello[0:2])
	pos := 34

	sidLen := int(hello[pos])
	pos++
	pos += sidLen

	if pos+2 > len(hello) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2
	ciphers := parseUint16List(hello[pos : pos+csLen])
	pos += csLen

	if pos >= len(hello) {
		return ""
	}
	compLen := int(hello[pos])
	pos++
	pos += compLen

	var extensions []uint16
	var curves []uint16
	var pointFormats []uint8

	if pos+2 <= len(hello) {
		extLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
		pos += 2
		extData := hello[pos : pos+extLen]
		extensions, curves, pointFormats = parseExtensions(extData)
	}

	parts := []string{
		fmt.Sprintf("%d", version),
		joinUint16(ciphers),
		joinUint16(extensions),
		joinUint16(curves),
		joinUint8(pointFormats),
	}
	sum := md5.Sum([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(sum[:])
}

// JA4 вычисляет JA4-отпечаток TLS ClientHello (упрощённый вариант по спецификации FoxIO).
func JA4(record []byte) string {
	if len(record) < 5 {
		return ""
	}
	payload := record[5:]
	if len(payload) < 4 || payload[0] != 0x01 {
		return ""
	}

	helloLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	hello := payload[4:]
	if len(hello) < helloLen {
		return ""
	}
	hello = hello[:helloLen]
	if len(hello) < 34 {
		return ""
	}

	version := binary.BigEndian.Uint16(hello[0:2])
	sni := extractSNI(hello)
	pos := 34

	sidLen := int(hello[pos])
	pos++
	pos += sidLen

	if pos+2 > len(hello) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2
	ciphers := parseUint16List(hello[pos : pos+csLen])
	pos += csLen

	if pos >= len(hello) {
		return ""
	}
	compLen := int(hello[pos])
	pos++
	pos += compLen

	var extensions []uint16
	var alpn string
	if pos+2 <= len(hello) {
		extLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
		pos += 2
		extensions, _, _ = parseExtensions(hello[pos : pos+extLen])
		alpn = extractALPN(hello[pos : pos+extLen])
	}

	proto := "t"
	if alpn == "h2" {
		proto = "h2"
	}

	versionToken := ja4VersionToken(version, extensions)
	cipherCount := fmt.Sprintf("%02d", min(len(ciphers), 99))
	extCount := fmt.Sprintf("%02d", min(len(extensions), 99))

	cipherHash := ja4SortedHashUint16(ciphers)
	extHash := ja4SortedHashUint16(extensions)

	sniHash := "00000000"
	if sni != "" {
		sum := sha256Hex12(strings.ToLower(sni))
		sniHash = sum
	}

	return fmt.Sprintf("%s%s%s_%s_%s_%s", proto, versionToken, cipherCount+extCount, cipherHash, extHash, sniHash)
}

func ja4VersionToken(version uint16, extensions []uint16) string {
	for _, ext := range extensions {
		if ext == extSupportedVersions {
			return "13"
		}
	}
	switch version {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	default:
		return "00"
	}
}

func ja4SortedHashUint16(values []uint16) string {
	if len(values) == 0 {
		return "000000000000"
	}
	cp := append([]uint16(nil), values...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	parts := make([]string, len(cp))
	for i, v := range cp {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return sha256Hex12(strings.Join(parts, ","))
}

func sha256Hex12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

func extractSNI(hello []byte) string {
	pos := 34
	sidLen := int(hello[pos])
	pos++
	pos += sidLen
	if pos+2 > len(hello) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2 + csLen
	if pos >= len(hello) {
		return ""
	}
	compLen := int(hello[pos])
	pos++
	pos += compLen
	if pos+2 > len(hello) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2
	return parseSNI(hello[pos : pos+extLen])
}

func extractALPN(extensions []byte) string {
	pos := 0
	for pos+4 <= len(extensions) {
		extType := binary.BigEndian.Uint16(extensions[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(extensions[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > len(extensions) {
			break
		}
		if extType == extALPN {
			data := extensions[pos : pos+extLen]
			if len(data) < 2 {
				return ""
			}
			listLen := int(binary.BigEndian.Uint16(data[0:2]))
			data = data[2:]
			if len(data) < listLen || listLen == 0 {
				return ""
			}
			nameLen := int(data[0])
			if 1+nameLen > len(data) {
				return ""
			}
			return string(data[1 : 1+nameLen])
		}
		pos += extLen
	}
	return ""
}

func parseUint16List(data []byte) []uint16 {
	out := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		out = append(out, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return out
}

func parseExtensions(data []byte) (extensions []uint16, curves []uint16, pointFormats []uint8) {
	pos := 0
	for pos+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > len(data) {
			break
		}
		extensions = append(extensions, extType)
		extData := data[pos : pos+extLen]
		switch extType {
		case extSupportedGroups:
			if len(extData) >= 2 {
				listLen := int(binary.BigEndian.Uint16(extData[0:2]))
				curves = parseUint16List(extData[2 : 2+listLen])
			}
		case extECPointFormats:
			if len(extData) >= 1 {
				listLen := int(extData[0])
				for _, b := range extData[1 : 1+listLen] {
					pointFormats = append(pointFormats, b)
				}
			}
		}
		pos += extLen
	}
	return extensions, curves, pointFormats
}

func joinUint16(values []uint16) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

func joinUint8(values []uint8) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
