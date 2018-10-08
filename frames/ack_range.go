package frames

import "github.com/Vishista/mp-quic/protocol"

// AckRange is an ACK range
type AckRange struct {
	FirstPacketNumber protocol.PacketNumber
	LastPacketNumber  protocol.PacketNumber
}
