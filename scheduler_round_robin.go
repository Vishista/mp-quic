package quic

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

func roundRobinScheduling(auxiliaryData SchedulerAuxiliaryData, sc *Scheduler) (map[int][]frames.Frame, error) {
	payloadPathMap := make(map[int][]frames.Frame)
	payloadSpaceLeftMap := make(map[int]protocol.ByteCount)
	publicHeadersLength := auxiliaryData.PublicHeadersLength
	allowedPaths := auxiliaryData.AllowedPaths
	ackFrames := auxiliaryData.AckFramesMap
	stopWaitingFrames := auxiliaryData.StopWaitingFramesMap
	//////////
	//Adding SWF and ACK to the packets
	//////////
	for _, pathId := range allowedPaths {
		payloadSpaceLeft := protocol.MaxFrameAndPublicHeaderSize - publicHeadersLength[pathId]
		stopWaitingFrame, hasSWF := stopWaitingFrames[pathId]
		ackFrame, hasAck := ackFrames[pathId]
		var payloadFrames []frames.Frame
		if hasSWF {
			payloadFrames, payloadSpaceLeft, _ = sc.appendFrame(payloadFrames, payloadSpaceLeft, stopWaitingFrame)
		}
		if hasAck {
			payloadFrames, payloadSpaceLeft, _ = sc.appendFrame(payloadFrames, payloadSpaceLeft, ackFrame)
		}
		payloadPathMap[pathId] = payloadFrames
		payloadSpaceLeftMap[pathId] = payloadSpaceLeft
	}
	//////////
	//Adding Control Frames (RoundRobin)
	//////////
	var noSpaceLeft bool
	iterator := 0
	for isSpaceLeft(payloadSpaceLeftMap) && len(sc.controlFrames) > 0 {
		if iterator == len(allowedPaths) {
			iterator = 0
		}
		pathId := allowedPaths[iterator]
		payloadFrames := payloadPathMap[pathId]
		payloadSpaceLeft := payloadSpaceLeftMap[pathId]
		frame := sc.controlFrames[len(sc.controlFrames)-1]
		payloadFrames, payloadSpaceLeft, noSpaceLeft = sc.appendFrame(payloadFrames, payloadSpaceLeft, frame)
		if noSpaceLeft { //if any path packet has no space left...
			break //this usually does not happen, in case it happens we dont care and send the remaining control frames in the next round
		}
		sc.controlFrames = sc.controlFrames[:len(sc.controlFrames)-1]
		payloadPathMap[pathId] = payloadFrames
		payloadSpaceLeftMap[pathId] = payloadSpaceLeft
		iterator++
	}
	if !auxiliaryData.CanSendData {
		return payloadPathMap, nil
	}
	//////////
	//Increasing size by 2
	//////////
	for _, pathId := range allowedPaths {
		payloadSpaceLeftMap[pathId] = payloadSpaceLeftMap[pathId] + 2 //original implementatio did the same
	}

	//////////
	//Adding Frames for retransmission (RoundRobin)
	//////////
	lastFrameMap := make(map[int]*frames.StreamFrame)
	//schedule frames for retransmission
	iterator = 0
	for isSpaceLeft(payloadSpaceLeftMap) && sc.streamFramer.HasFramesForRetransmission() {
		if iterator == len(allowedPaths) {
			iterator = 0
		}
		pathId := allowedPaths[iterator]
		frame, spaceLeft := sc.streamFramer.PopRetransmissionFrame(payloadSpaceLeftMap[pathId])
		payloadSpaceLeftMap[pathId] = spaceLeft
		if frame != nil {
			lastFrameMap[pathId] = frame
			payloadPathMap[pathId] = append(payloadPathMap[pathId], frame) // should not be too large since PopRetransmissionFrame checked the size
		}
		iterator++
	}

	/*//collecting the pending data to send
	//TODO use bundledData for better stream_scheduler
	bundledSendData, err := sc.getBundledSendData()
	if err != nil {
		return nil, err
	}*/

	//////////
	//Adding StreamFrames (RoundRobin)
	//////////
	iterator = 0
	fn := func(s *stream) (bool, error) {
		//could try to optimize: iterate over paths with space left only
		for {
			if iterator == len(allowedPaths) {
				iterator = 0
			}
			pathId := allowedPaths[iterator]
			frame, spaceLeft := sc.streamFramer.PopNormalFrame(payloadSpaceLeftMap[pathId], s)
			payloadSpaceLeftMap[pathId] = spaceLeft
			if frame != nil {
				lastFrameMap[pathId] = frame
				payloadPathMap[pathId] = append(payloadPathMap[pathId], frame) // should not be too large since PopNormalFrame checked the size
			}
			iterator++
			//if no more payload space is left, return false (dont continue to read from other streams)
			if !isSpaceLeft(payloadSpaceLeftMap) {
				return false, nil
			}
			//if payload space is left, but this stream has no data, continue with another stream
			if s.lenOfDataForWriting() <= 0 || s == nil || s.streamID == 1 {
				return true, nil
			}
		}
	}
	sc.streamSchedulingFunction(sc.streamsMap, fn)
	for _, frame := range lastFrameMap {
		//DataLenPresent false indicates that the STREAM frame extends to the end of the Packet.
		frame.DataLenPresent = false
	}
	return payloadPathMap, nil
}

/*
func scheduleSending_OLD(auxiliaryData SchedulerAuxiliaryData) (map[int][]frames.Frame, error) {
	payloadPathMap := make(map[int][]frames.Frame)

	ackFrames := auxiliaryData.AckFramesMap
	publicHeadersLength := auxiliaryData.PublicHeadersLength
	allowedPaths := auxiliaryData.AllowedPaths
	stopWaitingFrames := auxiliaryData.StopWaitingFramesMap

	//TODO next "copy" composeNextPacket with own logic of scheduling
	for pathId := range allowedPaths {

		var payloadFrames []frames.Frame

		payloadSpaceLeft := protocol.MaxFrameAndPublicHeaderSize - publicHeadersLength[pathId]
		stopWaitingFrame, hasSWF := stopWaitingFrames[pathId]
		ackFrame, hasAck := ackFrames[pathId]
		noSpaceLeft := false
		if hasSWF {
			payloadFrames, payloadSpaceLeft, _ = sc.appendFrame(payloadFrames, payloadSpaceLeft, stopWaitingFrame)
		}
		if hasAck {
			payloadFrames, payloadSpaceLeft, _ = sc.appendFrame(payloadFrames, payloadSpaceLeft, ackFrame)
		}

		//the first allowed Path gets all control Frames in this implementation
		//TODO schedule this
		for len(sc.controlFrames) > 0 {
			frame := sc.controlFrames[len(sc.controlFrames)-1]
			payloadFrames, payloadSpaceLeft, noSpaceLeft = sc.appendFrame(payloadFrames, payloadSpaceLeft, frame)
			if noSpaceLeft {
				break
			}
			sc.controlFrames = sc.controlFrames[:len(sc.controlFrames)-1]
		}

		if noSpaceLeft || !auxiliaryData.CanSendData {
			payloadPathMap[pathId] = payloadFrames
			continue
		}

		//the first allowed Path gets all frames in this implementation
		//TODO schedule this
		payloadSpaceLeft += 2
		fs := sc.streamFramer.PopStreamFrames(payloadSpaceLeft)
		if len(fs) != 0 {
			fs[len(fs)-1].DataLenPresent = false
		}

		for _, f := range fs {
			payloadFrames = append(payloadFrames, f)
		}
		payloadPathMap[pathId] = payloadFrames

	}
	return payloadPathMap, nil
}

// RoundRobinIterate executes the streamLambda for every open stream, until the streamLambda returns false
// It uses a round-robin-like scheduling to ensure that every stream is considered fairly
// It prioritizes the crypto- and the header-stream (StreamIDs 1 and 3)
func (rr *RoundRobinScheduler) RoundRobinIterate(fn streamLambda) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	numStreams := uint32(len(m.streams))
	startIndex := m.roundRobinIndex

	for _, i := range []protocol.StreamID{1, 3} {
		cont, err := m.iterateFunc(i, fn)
		if err != nil && err != errMapAccess {
			return err
		}
		if !cont {
			return nil
		}
	}

	for i := uint32(0); i < numStreams; i++ {
		streamID := m.openStreams[(i+startIndex)%numStreams]
		if streamID == 1 || streamID == 3 {
			continue
		}

		cont, err := m.iterateFunc(streamID, fn)
		if err != nil {
			return err
		}
		m.roundRobinIndex = (m.roundRobinIndex + 1) % numStreams
		if !cont {
			break
		}
	}
	return nil
}

func (rr *RoundRobinScheduler) iterateFunc(streamID protocol.StreamID, fn streamLambda) (bool, error) {
	str, ok := m.streams[streamID]
	if !ok {
		return true, errMapAccess
	}
	return fn(str)
}
*/
/*
func (rr *RoundRobinScheduler) AddNewPath(pathId int) {
	if pathId > rr.maxPathId {
		rr.maxPathId = pathId
	}
}

type allowedLambda func(int) bool


func (rr *RoundRobinScheduler) GetPathForSending(allowedFunction allowedLambda) int {
	counter := 0
	for {
		rr.lastUsedPath++
		counter++
		if rr.lastUsedPath > rr.maxPathId {
			rr.lastUsedPath = 0
		}
		if allowedFunction(rr.lastUsedPath) {
			return rr.lastUsedPath
		}

		if counter > rr.maxPathId {
			break
		}
	}
	return -1
}
*/
