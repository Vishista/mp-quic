package quic

import (
	"github.com/Vishista/mp-quic/frames"
	"github.com/Vishista/mp-quic/protocol"
)

func minRTTScheduling(auxiliaryData SchedulerAuxiliaryData, sc *Scheduler) (map[int][]frames.Frame, error) {
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

	//Get the Path with the mininal RountTripTime
	pathId := sc.rttStatsManager.GetMinRTTPath(allowedPaths)
	//////////
	//Adding Control Frames (minRTT)
	//////////
	var noSpaceLeft bool
	for len(sc.controlFrames) > 0 {
		payloadFrames := payloadPathMap[pathId]
		payloadSpaceLeft := payloadSpaceLeftMap[pathId]
		frame := sc.controlFrames[len(sc.controlFrames)-1]
		payloadFrames, payloadSpaceLeft, noSpaceLeft = sc.appendFrame(payloadFrames, payloadSpaceLeft, frame)
		if noSpaceLeft {
			break
		}
		sc.controlFrames = sc.controlFrames[:len(sc.controlFrames)-1]
		payloadPathMap[pathId] = payloadFrames
		payloadSpaceLeftMap[pathId] = payloadSpaceLeft
	}

	if !auxiliaryData.CanSendData {
		return payloadPathMap, nil
	}
	//////////
	//Increasing size by 2
	//////////
	payloadSpaceLeftMap[pathId] = payloadSpaceLeftMap[pathId] + 2 //original implementatio did the same

	//////////
	//Adding Frames for retransmission (minRTT)
	//////////
	lastFrameMap := make(map[int]*frames.StreamFrame)
	//schedule frames for retransmission
	for sc.streamFramer.HasFramesForRetransmission() {
		frame, spaceLeft := sc.streamFramer.PopRetransmissionFrame(payloadSpaceLeftMap[pathId])
		payloadSpaceLeftMap[pathId] = spaceLeft
		if frame != nil {
			lastFrameMap[pathId] = frame
			payloadPathMap[pathId] = append(payloadPathMap[pathId], frame) // should not be too large since PopRetransmissionFrame checked the size
		}
		if spaceLeft == 0 || frame == nil {
			break
		}
	}

	//////////
	//Adding StreamFrames (minRTT)
	//////////
	fn := func(s *stream) (bool, error) {
		//could try to optimize: iterate over paths with space left only
		for {
			frame, spaceLeft := sc.streamFramer.PopNormalFrame(payloadSpaceLeftMap[pathId], s)
			payloadSpaceLeftMap[pathId] = spaceLeft
			if frame != nil {
				lastFrameMap[pathId] = frame
				payloadPathMap[pathId] = append(payloadPathMap[pathId], frame) // should not be too large since PopNormalFrame checked the size
			}
			//if no more payload space is left, return false (dont continue to read from other streams)
			if payloadSpaceLeftMap[pathId] <= 0 {
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
