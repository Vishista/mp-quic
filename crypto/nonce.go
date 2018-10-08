package crypto

import (
	"encoding/binary"

	"github.com/Vishista/mp-quic/protocol"
)

func makeNonce(iv []byte, packetNumber protocol.PacketNumber) []byte {
	res := make([]byte, 12)
	copy(res[0:4], iv)
	binary.LittleEndian.PutUint64(res[4:12], uint64(packetNumber))
	return res
}
