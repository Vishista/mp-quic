package quic

import (
	"github.com/Vishista/mp-quic/frames"
	"github.com/Vishista/mp-quic/protocol"
)

type SchedulerAuxiliaryData struct {
	AllowedPaths            []int
	PathsWithRetransmission []int
	AckFramesMap            map[int]*frames.AckFrame
	StopWaitingFramesMap    map[int]*frames.StopWaitingFrame
	PublicHeadersLength     map[int]protocol.ByteCount
	CanSendData             bool
}

type SchedulerSendData struct {
	StreamId       protocol.StreamID
	Priority       protocol.PriorityParam
	DataByteLength protocol.ByteCount
}
type bundledSendData struct {
	Priority       protocol.PriorityParam
	DataByteLength protocol.ByteCount
}
