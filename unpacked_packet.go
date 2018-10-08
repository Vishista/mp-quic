package quic

import (
	"github.com/Vishista/mp-quic/frames"
	"github.com/Vishista/mp-quic/protocol"
)

type unpackedPacket struct {
	encryptionLevel protocol.EncryptionLevel
	frames          []frames.Frame
}

func (u *unpackedPacket) IsRetransmittable() bool {
	for _, f := range u.frames {
		switch f.(type) {
		case *frames.StreamFrame:
			return true
		case *frames.RstStreamFrame:
			return true
		case *frames.WindowUpdateFrame:
			return true
		case *frames.BlockedFrame:
			return true
		case *frames.PingFrame:
			return true
		case *frames.GoawayFrame:
			return true
		}
	}
	return false
}
