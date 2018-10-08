package ackhandler

import (
	"time"

	"github.com/Vishista/mp-quic/frames"
	"github.com/Vishista/mp-quic/protocol"
)

// SentPacketHandler handles ACKs received for outgoing packets
type SentPacketHandler interface {
	SentPacket(packet *Packet) error
	ReceivedAck(ackFrame *frames.AckFrame, withPacketNumber protocol.PacketNumber, recvTime time.Time) error

	SendingAllowed(int) bool
	TrackedSentPackets() int
	HasRetransmission() bool
	GetStopWaitingFrame(force bool) *frames.StopWaitingFrame
	DequeuePacketForRetransmission() (packet *Packet)
	GetLeastUnacked() protocol.PacketNumber

	GetAlarmTimeout() time.Time
	OnAlarm()
}

// ReceivedPacketHandler handles ACKs needed to send for incoming packets
type ReceivedPacketHandler interface {
	ReceivedPacket(packetNumber protocol.PacketNumber, shouldInstigateAck bool) error
	ReceivedStopWaiting(*frames.StopWaitingFrame) error

	GetAckFrame() *frames.AckFrame
}
