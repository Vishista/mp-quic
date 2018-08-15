package quic

import (
	"github.com/lucas-clemente/quic-go/frames"
)

// ReceivedPacketHandler handles ACKs needed to send for incoming packets
type SchedulerInterface interface {
	AddSendData(SchedulerSendData)
	AddControlFrames([]frames.Frame)
	IsConnectionClose() bool
	GetConnectionCloseFrame() []frames.Frame
	SetConnectionCloseFrame(*frames.ConnectionCloseFrame)
	QueueControlFrameForNextPacket(frames.Frame)
	IsCryptoStreamFrame() bool
	ComposePayloadForSending(SchedulerAuxiliaryData) (map[int][]frames.Frame, error)
	ComposeCryptoPayload(auxiliaryData SchedulerAuxiliaryData) (map[int][]frames.Frame, error)
}

/*type streamFramer interface {
	PopStreamFrames(protocol.ByteCount) []*frames.StreamFrame //will be removed
	PopBlockedFrame() *frames.BlockedFrame
	HasCryptoStreamFrame() bool
	PopCryptoStreamFrame(protocol.ByteCount) *frames.StreamFrame
	HasFramesForRetransmission() bool
	PopRetransmissionFrame(protocol.ByteCount) (*frames.StreamFrame, protocol.ByteCount)
	PopNormalFrame(protocol.ByteCount, protocol.StreamID) (*frames.StreamFrame, protocol.ByteCount, error)
}

type streamLambda func(*stream) (bool, error)
type roundRobinStreamScheduler interface {
	RoundRobinIterate(streamLambda) error
}*/
