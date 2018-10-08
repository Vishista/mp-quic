package quic

import (
	"github.com/Vishista/mp-quic/frames"
	"github.com/Vishista/mp-quic/protocol"
)

func hobschedulingV2(auxiliaryData SchedulerAuxiliaryData, sc *Scheduler) (map[int][]frames.Frame, error) {
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
			var pathId int
			if s.streamID == protocol.StreamID(7) {
				pathId = 0
				space, ok := payloadSpaceLeftMap[pathId]
				if !contains(allowedPaths, pathId) || !ok {
					return true, nil
				}
				if space <= protocol.ByteCount(0) {
					return true, nil
				}
			} else {
				pathId = allowedPaths[iterator]
				iterator++
			}
			frame, spaceLeft := sc.streamFramer.PopNormalFrame(payloadSpaceLeftMap[pathId], s)
			payloadSpaceLeftMap[pathId] = spaceLeft
			if frame != nil {
				lastFrameMap[pathId] = frame
				payloadPathMap[pathId] = append(payloadPathMap[pathId], frame) // should not be too large since PopNormalFrame checked the size
			}
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
