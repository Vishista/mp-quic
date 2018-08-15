package quic

import (
	"errors"
	"sync"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
)

type Scheduler struct {
	dataToSend               []SchedulerSendData
	controlFrames            []frames.Frame
	streamFramer             *streamFramer
	streamsMap               *streamsMap
	version                  protocol.VersionNumber
	mutex                    sync.Mutex
	rttStatsManager          *congestion.RTTStatsManager
	schedulingFunction       schedulerFunctionLambda
	streamSchedulingFunction streamSchedulerFunctionLambda
}
type schedulerFunctionLambda func(SchedulerAuxiliaryData, *Scheduler) (map[int][]frames.Frame, error)
type streamSchedulerFunctionLambda func(m *streamsMap, fn streamLambda) error

func NewScheduler(scheduler string, streamScheduler string, streamFramer *streamFramer, streamsMap *streamsMap, version protocol.VersionNumber, rttStatsManager *congestion.RTTStatsManager) *Scheduler {
	sc := new(Scheduler)
	sc.streamFramer = streamFramer
	sc.streamsMap = streamsMap
	sc.version = version
	sc.rttStatsManager = rttStatsManager
	switch scheduler {
	case "rr":
		sc.schedulingFunction = roundRobinScheduling
		utils.Infof("Using a RoundRobin Scheduler...")
	case "mrtt":
		sc.schedulingFunction = minRTTScheduling
		utils.Infof("Using a MinRTT Scheduler...")
	case "hob":
		sc.schedulingFunction = hobscheduling
		utils.Infof("TESTING HOB - SCHEDULER USED")
	case "hob2":
		sc.schedulingFunction = hobschedulingV2
		utils.Infof("TESTING HOB V2 - SCHEDULER USED")
	default:
		sc.schedulingFunction = roundRobinScheduling
		utils.Infof("%s is not a supported Scheduler! Using RoundRobin Scheduler as default", scheduler)
	}
	switch streamScheduler {
	case "rr":
		sc.streamSchedulingFunction = RoundRobinIterate
		utils.Infof("Using a RoundRobin StreamScheduler...")
	case "prio":
		sc.streamSchedulingFunction = PrioritizedStreamsIterate
		utils.Infof("Using a PrioritizedStream Scheduler...")
	case "sprio":
		sc.streamSchedulingFunction = StrictPrioritizedStreamsIterate
		utils.Infof("Using a StrictPrioritizedStream Scheduler...")
	case "hob2":
		sc.streamSchedulingFunction = HOBTestScheduler
		utils.Infof("TESTING HOB V2 - SCHEDULER USED...")
	default:
		sc.streamSchedulingFunction = RoundRobinIterate
		utils.Infof("%s is not a supported Scheduler! Using RoundRobin StreamScheduler as default", streamScheduler)
	}

	return sc
}

func (sc *Scheduler) AddSendData(newDataToSend SchedulerSendData) {
	sc.mutex.Lock()
	sc.dataToSend = append(sc.dataToSend, newDataToSend)
	sc.mutex.Unlock()
}

func (sc *Scheduler) AddControlFrames(controlFrames []frames.Frame) {
	sc.controlFrames = append(sc.controlFrames, controlFrames...)
}
func (sc *Scheduler) QueueControlFrameForNextPacket(f frames.Frame) {
	sc.controlFrames = append(sc.controlFrames, f)
}

func (sc *Scheduler) IsConnectionClose() bool {
	var isConnectionClose bool
	if len(sc.controlFrames) == 1 {
		_, isConnectionClose = sc.controlFrames[0].(*frames.ConnectionCloseFrame)
	}
	return isConnectionClose
}

func (sc *Scheduler) GetConnectionCloseFrame() []frames.Frame {
	return []frames.Frame{sc.controlFrames[0]}
}

func (sc *Scheduler) SetConnectionCloseFrame(ccf *frames.ConnectionCloseFrame) {
	sc.controlFrames = []frames.Frame{ccf}
}
func (sc *Scheduler) IsCryptoStreamFrame() bool {
	return sc.streamFramer.HasCryptoStreamFrame()
}

func (sc *Scheduler) ComposeCryptoPayload(auxiliaryData SchedulerAuxiliaryData) (map[int][]frames.Frame, error) {
	payloadPathMap := make(map[int][]frames.Frame)
	sc.streamFramer.HasCryptoStreamFrame()
	//this is the simplest solution right now
	//if we have crypto stream frames, just compose a single packet on any allowed path.
	pathId := auxiliaryData.AllowedPaths[0]
	maxLen := protocol.MaxFrameAndPublicHeaderSize - protocol.NonForwardSecurePacketSizeReduction - auxiliaryData.PublicHeadersLength[pathId]
	payloadPathMap[pathId] = []frames.Frame{sc.streamFramer.PopCryptoStreamFrame(maxLen)}
	return payloadPathMap, nil

}
func (sc *Scheduler) ComposePayloadForSending(auxiliaryData SchedulerAuxiliaryData) (map[int][]frames.Frame, error) {
	payloadPathMap, err := sc.schedulingFunction(auxiliaryData, sc)
	if err != nil {
		return nil, err
	}
	//queue the blocked frames for the next packet
	for b := sc.streamFramer.PopBlockedFrame(); b != nil; b = sc.streamFramer.PopBlockedFrame() {
		sc.controlFrames = append(sc.controlFrames, b)
	}
	return payloadPathMap, nil
}

//This is only for Ack,Control and StopWaiting Frames
func (sc *Scheduler) appendFrame(payloadFrames []frames.Frame, payloadSpaceLeft protocol.ByteCount, frame frames.Frame) ([]frames.Frame, protocol.ByteCount, bool) {
	if frame != nil {
		minLength, _ := frame.MinLength(sc.version)
		if minLength > payloadSpaceLeft {
			return payloadFrames, payloadSpaceLeft, true
		}
		payloadSpaceLeft -= minLength
		payloadFrames = append(payloadFrames, frame)
	}
	return payloadFrames, payloadSpaceLeft, false
}

func isSpaceLeft(spaceLeft map[int]protocol.ByteCount) bool {
	for _, value := range spaceLeft {
		if value > 0 {
			return true
		}
	}
	return false
}

func getMapKeys(mymap map[int]protocol.ByteCount) []int {
	keys := make([]int, 0, len(mymap))
	for k := range mymap {
		keys = append(keys, k)
	}
	return keys
}

//TODO for stream_scheduler: NOT USED YET
func (sc *Scheduler) getBundledSendData() (map[protocol.StreamID]bundledSendData, error) {
	//TODO check correctness
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	bundledData := make(map[protocol.StreamID]bundledSendData)
	for _, data := range sc.dataToSend {
		if existingData, ok := bundledData[data.StreamId]; ok {
			if bundledData[data.StreamId].Priority != data.Priority {
				return nil, errors.New("Scheduler: Bundle Send Information Error: Data of the same Stream must have same Priority")
			}
			existingData.DataByteLength += data.DataByteLength
			bundledData[data.StreamId] = existingData
		} else {
			var newDataBundle bundledSendData
			newDataBundle.DataByteLength = data.DataByteLength
			newDataBundle.Priority = data.Priority
			bundledData[data.StreamId] = newDataBundle
		}

	}
	return bundledData, nil
}
