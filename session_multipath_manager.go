package quic

import (
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
)

type multipathComponents struct {
	connection              connection
	sentPacketHandler       ackhandler.SentPacketHandler
	receivedPacketHandler   ackhandler.ReceivedPacketHandler
	nextAckScheduledTime    time.Time
	lastRcvdPacketNumber    protocol.PacketNumber
	largestRcvdPacketNumber protocol.PacketNumber
	lastNetworkActivityTime time.Time
	packetNumberGenerator   *packetNumberGenerator
}

// A Session is a QUIC session
type sessionMultipathManager struct {
	sessionPathMap  map[int]*multipathComponents
	nextPathId      int
	pathIdMap       map[string]int
	rttStatsManager *congestion.RTTStatsManager
}

func newSessionMultipathManager(connection connection) *sessionMultipathManager {
	sessionMultipathManager := new(sessionMultipathManager)
	sessionMultipathManager.nextPathId = 0
	sessionMultipathManager.sessionPathMap = make(map[int]*multipathComponents)
	sessionMultipathManager.pathIdMap = make(map[string]int)
	sessionMultipathManager.rttStatsManager = congestion.NewRTTStatsManager()
	sessionMultipathManager.addNewPath(connection)
	return sessionMultipathManager
}

//returns the pathId according to nextPathId variable
func (smm *sessionMultipathManager) addNewPath(connection connection) int {
	pathIdentified := connection.RemoteAddr().String() + connection.LocalAddr().String()
	smm.sessionPathMap[smm.nextPathId] = &multipathComponents{}
	smm.pathIdMap[pathIdentified] = smm.nextPathId
	smm.setup(smm.nextPathId, connection)
	smm.nextPathId++
	return smm.pathIdMap[pathIdentified]
}

func (smm *sessionMultipathManager) setup(pathId int, connection connection) error {
	now := time.Now()
	pathComponents, ok := smm.sessionPathMap[pathId]
	if ok {
		rttStats := congestion.NewRTTStats()
		smm.rttStatsManager.AddNewRTTStats(rttStats, pathId)
		pathComponents.connection = connection
		pathComponents.lastNetworkActivityTime = now
		pathComponents.sentPacketHandler = ackhandler.NewSentPacketHandler(rttStats)
		pathComponents.receivedPacketHandler = ackhandler.NewReceivedPacketHandler(getAlarmFunction(pathId, smm))
		pathComponents.packetNumberGenerator = newPacketNumberGenerator(protocol.SkipPacketAveragePeriodLength)

	} else {
		return nil
	}
	return nil
}

func getAlarmFunction(pathId int, smm *sessionMultipathManager) func(time.Time) {
	return func(t time.Time) {
		smm.setNextAckScheduledTime(pathId, t)
	}
}

func (smm *sessionMultipathManager) checkAlarmTimeouts(now time.Time) {
	for _, pathComponents := range smm.sessionPathMap {
		if timeout := pathComponents.sentPacketHandler.GetAlarmTimeout(); !timeout.IsZero() && timeout.Before(now) {
			// This could cause packets to be retransmitted, so check it before trying
			// to send packets.
			pathComponents.sentPacketHandler.OnAlarm()
		}
	}
}
func (smm *sessionMultipathManager) allNetworksIdl(idleTimeout time.Duration, now time.Time) bool {
	allNetworksIdle := true
	for _, pathComponents := range smm.sessionPathMap {
		if now.Sub(pathComponents.lastNetworkActivityTime) < idleTimeout {
			allNetworksIdle := false
			return allNetworksIdle
		}
	}
	return allNetworksIdle
}

////getPath
func (smm *sessionMultipathManager) getPathId(remoteAddress net.Addr, localAddress net.Addr) int {
	pathIdentified := remoteAddress.String() + localAddress.String()
	if path, ok := smm.pathIdMap[pathIdentified]; !ok {
		return -1
	} else {
		return path

	}
}

////receivedPacketHandler
func (smm *sessionMultipathManager) receivedPacketHandler(pathId int) ackhandler.ReceivedPacketHandler {
	return smm.sessionPathMap[pathId].receivedPacketHandler
}

////connection
func (smm *sessionMultipathManager) connection(pathId int) connection {
	return smm.sessionPathMap[pathId].connection
}

////receivedPacketHandler
func (smm *sessionMultipathManager) sentPacketHandler(pathId int) ackhandler.SentPacketHandler {
	return smm.sessionPathMap[pathId].sentPacketHandler
}

////receivedPacketHandler
func (smm *sessionMultipathManager) getRttStatsManager() *congestion.RTTStatsManager {
	return smm.rttStatsManager
}

////receivedPacketHandler
func (smm *sessionMultipathManager) packetNumberGenerator(pathId int) *packetNumberGenerator {
	return smm.sessionPathMap[pathId].packetNumberGenerator
}

////getRemoteAddress
func (smm *sessionMultipathManager) remoteAddress(pathId int) net.Addr {
	return smm.sessionPathMap[pathId].connection.RemoteAddr()
}

////lastNetworkActivityTime
func (smm *sessionMultipathManager) setLastNetworkActivityTime(pathId int, newTime time.Time) {
	smm.sessionPathMap[pathId].lastNetworkActivityTime = newTime
}
func (smm *sessionMultipathManager) getLastNetworkActivityTime(pathId int) time.Time {
	return smm.sessionPathMap[pathId].lastNetworkActivityTime
}

////nextAckScheduledTime
func (smm *sessionMultipathManager) setNextAckScheduledTime(pathId int, newTime time.Time) {
	smm.sessionPathMap[pathId].nextAckScheduledTime = newTime
}
func (smm *sessionMultipathManager) getNextAckScheduledTime(pathId int) time.Time {
	return smm.sessionPathMap[pathId].nextAckScheduledTime
}

////largestRcvdPacketNumber
func (smm *sessionMultipathManager) setLargestRcvdPacketNumber(pathId int, numb protocol.PacketNumber) {
	smm.sessionPathMap[pathId].largestRcvdPacketNumber = numb
}
func (smm *sessionMultipathManager) getLargestRcvdPacketNumber(pathId int) protocol.PacketNumber {
	return smm.sessionPathMap[pathId].largestRcvdPacketNumber
}

////lastRcvdPacketNumber
func (smm *sessionMultipathManager) setLastRcvdPacketNumber(pathId int, numb protocol.PacketNumber) {
	smm.sessionPathMap[pathId].lastRcvdPacketNumber = numb
}
func (smm *sessionMultipathManager) getLastRcvdPacketNumber(pathId int) protocol.PacketNumber {
	return smm.sessionPathMap[pathId].lastRcvdPacketNumber
}

func (smm *sessionMultipathManager) getAllowedPaths() []int {
	var allowedPaths []int
	trackedSentPackets := 0
	for _, id := range smm.pathIdMap {
		trackedSentPackets += smm.sentPacketHandler(id).TrackedSentPackets()
		if smm.sentPacketHandler(id).SendingAllowed(id) {
			allowedPaths = append(allowedPaths, id)
		}
	}
	if protocol.PacketNumber(trackedSentPackets) >= protocol.MaxTrackedSentPackets {
		var emptyList []int
		return emptyList
	}
	return allowedPaths
}

func (smm *sessionMultipathManager) getPathsWithRetransmissions() []int {
	var retransmissionPaths []int
	for _, id := range smm.pathIdMap {
		if smm.sentPacketHandler(id).HasRetransmission() {
			retransmissionPaths = append(retransmissionPaths, id)
		}
	}
	return retransmissionPaths
}

func (smm *sessionMultipathManager) Write(raw []byte, pathId int) error {
	err := smm.connection(pathId).Write(raw)
	return err
}

func (smm *sessionMultipathManager) GetTimerDeadline(idleTimeout time.Duration) time.Time {
	maxDeadline := time.Unix(1<<63-62135596801, 999999999)
	for _, id := range smm.pathIdMap {
		s := smm.sessionPathMap[id]
		deadline := s.lastNetworkActivityTime.Add(idleTimeout)
		if !s.nextAckScheduledTime.IsZero() {
			deadline = utils.MinTime(deadline, s.nextAckScheduledTime)
		}
		if lossTime := s.sentPacketHandler.GetAlarmTimeout(); !lossTime.IsZero() {
			deadline = utils.MinTime(deadline, lossTime)
		}
		maxDeadline = utils.MinTime(maxDeadline, deadline)
	}
	return maxDeadline
}
