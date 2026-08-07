package proxy

import (
	"errors"
	"strings"

	"github.com/RioTwWks/PhantomProxy/internal/faketls"
)

func classifyHandshakeError(err error) faketls.RejectReason {
	if err == nil {
		return ""
	}
	var pe *faketls.PolicyError
	if errors.As(err, &pe) {
		return pe.Reason
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "replay"):
		return faketls.RejectReasonReplay
	case strings.Contains(msg, "ja3"), strings.Contains(msg, "ja4"), strings.Contains(msg, "белом списке"):
		return faketls.RejectReasonFingerprint
	case strings.Contains(msg, "секрет"), strings.Contains(msg, "hmac"), strings.Contains(msg, "метка времени"):
		return faketls.RejectReasonSecret
	case strings.Contains(msg, "clienthello"), strings.Contains(msg, "tls"):
		return faketls.RejectReasonParse
	default:
		return faketls.RejectReasonSecret
	}
}

func (s *Server) recordTLSReject(err error) {
	if s.metrics == nil {
		return
	}
	reason := classifyHandshakeError(err)
	if reason == "" {
		reason = faketls.RejectReasonSecret
	}
	s.metrics.RecordTLSReject(string(reason))
	s.metrics.FakeTLSRejected().Inc()
}

func (s *Server) onHandshakeFailure(err error) {
	if s.rt.FingerprintRotator != nil {
		s.rt.FingerprintRotator.RecordFailure()
	}
	if s.rt.ServerHelloRotator != nil {
		s.rt.ServerHelloRotator.RecordFailure()
	}
	s.recordTLSReject(err)
}

func (s *Server) onHandshakeSuccess() {
	if s.rt.FingerprintRotator != nil {
		s.rt.FingerprintRotator.RecordSuccess()
	}
	if s.rt.ServerHelloRotator != nil {
		s.rt.ServerHelloRotator.RecordSuccess()
	}
}

func policyRejectError(ch *faketls.ClientHello, policy string) error {
	return faketls.CheckClientHelloPolicy(ch, policy)
}
