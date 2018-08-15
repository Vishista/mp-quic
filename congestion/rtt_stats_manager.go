package congestion

import (
	"time"
)

type RTTStatsManager struct {
	rttStatsMap map[int]*RTTStats
}

func NewRTTStatsManager() *RTTStatsManager {
	rttStatsManager := new(RTTStatsManager)
	rttStatsManager.rttStatsMap = make(map[int]*RTTStats)
	return rttStatsManager
}

func (rsm *RTTStatsManager) AddNewRTTStats(rttStats *RTTStats, pathId int) {
	rsm.rttStatsMap[pathId] = rttStats
}

// SmoothedRTT returns the smallest EWMA smoothed RTT of all paths for the connection.
// May return Zero if no valid updates have occurred.
// The method name is derivated from the rtt_stats.go SmoothedRTT() method
// and therefore the name is retained and even if MinSmoothedRTT would be a more descriptive term
func (rsm *RTTStatsManager) SmoothedRTT() time.Duration {
	minSmoothedRTT := time.Duration(9999999999) //9999999999 is like inf in RTT sence... (~10sec)
	//TODO Not tested
	for _, rttStats := range rsm.rttStatsMap {
		if minSmoothedRTT > rttStats.smoothedRTT && rttStats.smoothedRTT > 0 {
			minSmoothedRTT = rttStats.smoothedRTT
		}
	}
	return minSmoothedRTT
}

func (rsm *RTTStatsManager) GetMinRTTPath(allowedPaths []int) int {
	var minRtt_pathId int
	minRtt := time.Hour
	for _, pathId := range allowedPaths {
		rttStats := rsm.rttStatsMap[pathId]
		//> time.Duration(0) ensures that we already have a RTT measure for this path
		if minRtt > rttStats.SmoothedRTT() && rttStats.SmoothedRTT() > time.Duration(0) {
			minRtt_pathId = pathId
			minRtt = rttStats.SmoothedRTT()
		}
	}
	//if minRtt is still the initial value, no allowed path had a RTT measure and we just take the first allowed path
	if minRtt == time.Hour {
		minRtt_pathId = allowedPaths[0]
	}
	return minRtt_pathId
}
