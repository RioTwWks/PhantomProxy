package faketls

import (
	"encoding/binary"
	"fmt"
)

const (
	// ClientHelloPolicyAccept — принимать все ClientHello.
	ClientHelloPolicyAccept = "accept"
	// ClientHelloPolicyLog — логировать подозрительные, но принимать.
	ClientHelloPolicyLog = "log"
	// ClientHelloPolicyRejectFronting — отклонять подозрительные в fronting.
	ClientHelloPolicyRejectFronting = "reject_fronting"

	extECH uint16 = 0xfe0d
)

// RejectReason — причина отклонения ClientHello.
type RejectReason string

const (
	RejectReasonParse      RejectReason = "parse"
	RejectReasonReplay     RejectReason = "replay"
	RejectReasonSecret     RejectReason = "secret"
	RejectReasonFingerprint RejectReason = "fingerprint"
	RejectReasonECH        RejectReason = "ech"
	RejectReasonPolicy     RejectReason = "policy"
)

// PolicyError сигнализирует об отклонении по политике ClientHello.
type PolicyError struct {
	Reason RejectReason
	Detail string
}

func (e *PolicyError) Error() string {
	return fmt.Sprintf("client hello policy %s: %s", e.Reason, e.Detail)
}

// HasECH проверяет наличие ECH-расширения в ClientHello.
func HasECH(ch *ClientHello) bool {
	if ch == nil {
		return false
	}
	return hasExtension(ch.Raw, extECH)
}

func hasExtension(record []byte, want uint16) bool {
	if len(record) < 5 {
		return false
	}
	payload := record[5:]
	if len(payload) < 4 || payload[0] != 0x01 {
		return false
	}
	helloLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	hello := payload[4:]
	if len(hello) < helloLen {
		return false
	}
	hello = hello[:helloLen]
	if len(hello) < 34 {
		return false
	}
	pos := 34
	sidLen := int(hello[pos])
	pos++
	pos += sidLen
	if pos+2 > len(hello) {
		return false
	}
	csLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2 + csLen
	if pos >= len(hello) {
		return false
	}
	compLen := int(hello[pos])
	pos++
	pos += compLen
	if pos+2 > len(hello) {
		return false
	}
	extLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2
	extData := hello[pos : pos+extLen]

	p := 0
	for p+4 <= len(extData) {
		extType := binary.BigEndian.Uint16(extData[p : p+2])
		el := int(binary.BigEndian.Uint16(extData[p+2 : p+4]))
		p += 4
		if extType == want {
			return true
		}
		p += el
	}
	return false
}

// CheckClientHelloPolicy проверяет ClientHello по политике.
func CheckClientHelloPolicy(ch *ClientHello, policy string) error {
	if ch == nil || policy == "" || policy == ClientHelloPolicyAccept {
		return nil
	}
	if HasECH(ch) && policy == ClientHelloPolicyRejectFronting {
		return &PolicyError{Reason: RejectReasonECH, Detail: "ECH extension present"}
	}
	if policy == ClientHelloPolicyLog && HasECH(ch) {
		return nil
	}
	return nil
}
