package quic

import (
	"errors"

	"github.com/lucas-clemente/quic-go/protocol"
)

//This method looks for the stream with the highest priority
//look for the parent streams
//if parent stream has data, recursivly check
//returns stream id
func getHighestPriorityStream(bundledDataMap map[protocol.StreamID]bundledSendData) (protocol.StreamID, error) {
	var highestWeight uint8
	var highestPriorityStream protocol.StreamID
	var streamDep protocol.StreamID
	for id, bundledData := range bundledDataMap {
		if highestWeight < bundledData.Priority.Weight {
			highestWeight = bundledData.Priority.Weight
			highestPriorityStream = id
			streamDep = bundledData.Priority.StreamDep
		}
	}
	loopCounter := 0
	for {
		if streamDep == 0 {
			//no dependency
			break
		} else if _, hasData := bundledDataMap[streamDep]; !hasData {
			//The current stream depends on streamDep, but streamDep has no data pending
			break
		}
		if _, hasData := bundledDataMap[streamDep]; hasData {
			//The current stream depends on streamDep, and streamDep has data pending
			//Send the data of streamDep first
			highestPriorityStream = streamDep
			streamDep = bundledDataMap[streamDep].Priority.StreamDep
		}
		loopCounter++
		if loopCounter > 100 {
			//could lead to an endless loop if there is a loop in the Stream dependencies
			return 0, errors.New("Scheduler:Maybe Dependency loop detected")
		}
	}
	return highestPriorityStream, nil
}
