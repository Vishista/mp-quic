package quic

import (
	"github.com/Vishista/mp-quic/flowcontrol"
	"github.com/Vishista/mp-quic/frames"
	"github.com/Vishista/mp-quic/internal/utils"
	"github.com/Vishista/mp-quic/protocol"
)

type streamFramer struct {
	streamsMap *streamsMap

	flowControlManager flowcontrol.FlowControlManager

	retransmissionQueue []*frames.StreamFrame
	blockedFrameQueue   []*frames.BlockedFrame
}

func newStreamFramer(streamsMap *streamsMap, flowControlManager flowcontrol.FlowControlManager) *streamFramer {
	return &streamFramer{
		streamsMap:         streamsMap,
		flowControlManager: flowControlManager,
	}
}

func (f *streamFramer) AddFrameForRetransmission(frame *frames.StreamFrame) {
	f.retransmissionQueue = append(f.retransmissionQueue, frame)
}

func (f *streamFramer) PopBlockedFrame() *frames.BlockedFrame {
	if len(f.blockedFrameQueue) == 0 {
		return nil
	}
	frame := f.blockedFrameQueue[0]
	f.blockedFrameQueue = f.blockedFrameQueue[1:]
	return frame
}

func (f *streamFramer) HasFramesForRetransmission() bool {
	return len(f.retransmissionQueue) > 0
}

func (f *streamFramer) HasCryptoStreamFrame() bool {
	// TODO(#657): Flow control
	cs, _ := f.streamsMap.GetOrOpenStream(1)
	return cs.lenOfDataForWriting() > 0
}

// TODO(lclemente): This is somewhat duplicate with the normal path for generating frames.
// TODO(#657): Flow control
func (f *streamFramer) PopCryptoStreamFrame(maxLen protocol.ByteCount) *frames.StreamFrame {
	if !f.HasCryptoStreamFrame() {
		return nil
	}
	cs, _ := f.streamsMap.GetOrOpenStream(1)
	frame := &frames.StreamFrame{
		StreamID: 1,
		Offset:   cs.writeOffset,
	}
	frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever) // can never error
	frame.Data = cs.getDataForWriting(maxLen - frameHeaderBytes)
	return frame
}

//spaceLeft could be replaced with desired frame size, so scheduler has more power over the framing
func (f *streamFramer) PopRetransmissionFrame(spaceLeft protocol.ByteCount) (*frames.StreamFrame, protocol.ByteCount) {
	frame := f.retransmissionQueue[0]
	frame.DataLenPresent = true

	frameHeaderLen, _ := frame.MinLength(protocol.VersionWhatever) // can never error
	if spaceLeft <= frameHeaderLen {
		//we set spaceLeft to 0 because it can't even hold a header
		spaceLeft = 0
		return nil, spaceLeft
	}

	spaceLeft -= frameHeaderLen

	splitFrame := maybeSplitOffFrame(frame, spaceLeft)
	if splitFrame != nil { // StreamFrame was split
		spaceLeft -= splitFrame.DataLen()
		return splitFrame, spaceLeft
	}

	f.retransmissionQueue = f.retransmissionQueue[1:]
	spaceLeft -= frame.DataLen()
	return frame, spaceLeft
}

//spaceLeft could be replaced with desired frame size, so scheduler has more power over the framing
func (f *streamFramer) PopNormalFrame(spaceLeft protocol.ByteCount, s *stream) (*frames.StreamFrame, protocol.ByteCount) {
	if spaceLeft == 0 {
		return nil, spaceLeft
	}
	frame := &frames.StreamFrame{DataLenPresent: true}

	if s == nil || s.streamID == 1 /* crypto stream is handled separately */ {
		return nil, spaceLeft
	}

	frame.StreamID = s.streamID
	frame.Offset = s.writeOffset
	frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever)

	if spaceLeft <= frameHeaderBytes {
		spaceLeft = 0
		return nil, spaceLeft
	}
	maxLen := spaceLeft - frameHeaderBytes

	var sendWindowSize protocol.ByteCount
	if s.lenOfDataForWriting() != 0 {
		//can lead to an infinite loop if we have space left, data left but not window
		sendWindowSize, _ = f.flowControlManager.SendWindowSize(s.streamID)
		maxLen = utils.MinByteCount(maxLen, sendWindowSize)
	}

	if maxLen == 0 {
		// this solves the infinite loop problem of the flowController
		spaceLeft = 0
		return nil, spaceLeft
	}

	data := s.getDataForWriting(maxLen)

	// This is unlikely, but check it nonetheless, the scheduler might have jumped in. Seems to happen in ~20% of cases in the tests.
	shouldSendFin := s.shouldSendFin()
	if data == nil && !shouldSendFin {
		return nil, spaceLeft
	}

	if shouldSendFin {
		frame.FinBit = true
		s.sentFin()
	}

	frame.Data = data
	f.flowControlManager.AddBytesSent(s.streamID, protocol.ByteCount(len(data)))

	// Finally, check if we are now FC blocked and should queue a BLOCKED frame
	if f.flowControlManager.RemainingConnectionWindowSize() == 0 {
		// We are now connection-level FC blocked
		f.blockedFrameQueue = append(f.blockedFrameQueue, &frames.BlockedFrame{StreamID: 0})
	} else if !frame.FinBit && sendWindowSize-frame.DataLen() == 0 {
		// We are now stream-level FC blocked
		f.blockedFrameQueue = append(f.blockedFrameQueue, &frames.BlockedFrame{StreamID: s.StreamID()})
	}

	spaceLeft = spaceLeft - frameHeaderBytes - frame.DataLen()

	return frame, spaceLeft
}

// maybeSplitOffFrame removes the first n bytes and returns them as a separate frame. If n >= len(frame), nil is returned and nothing is modified.
func maybeSplitOffFrame(frame *frames.StreamFrame, n protocol.ByteCount) *frames.StreamFrame {
	if n >= frame.DataLen() {
		return nil
	}

	defer func() {
		frame.Data = frame.Data[n:]
		frame.Offset += n
	}()

	return &frames.StreamFrame{
		FinBit:         false,
		StreamID:       frame.StreamID,
		Offset:         frame.Offset,
		Data:           frame.Data[:n],
		DataLenPresent: frame.DataLenPresent,
	}
}
