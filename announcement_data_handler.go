package quic

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"strings"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
)

/*
An Announcement Packet is of type receivedPacket with a special data format:
data length: 6 byte
first 4 byte: IP Address
last 2 byte: Port number
*/

func parseAnnouncedAddress(packet *receivedPacket) *net.UDPAddr {
	data := packet.data
	ip := net.IPv4(data[0], data[1], data[2], data[3]).To4()
	port := int(binary.BigEndian.Uint16(data[4:]))
	var udpAddress net.UDPAddr
	udpAddress.IP = ip
	udpAddress.Port = int(port)
	return &udpAddress
}

func getAnnouncementDataFromString(address string) []byte {
	addressParts := strings.Split(address, ":")
	ipadresstosend := net.ParseIP(addressParts[0]).To4()
	portbyte := make([]byte, 2)
	port, _ := strconv.ParseInt(addressParts[1], 0, 32)
	binary.BigEndian.PutUint16(portbyte, uint16(port))
	var data []byte
	data = append(ipadresstosend, portbyte[0], portbyte[1])
	return data
}

func composeAnnouncementOnCurrentPath(connectionID protocol.ConnectionID, address net.Addr, pers protocol.Perspective) []byte {
	fullReply := &bytes.Buffer{}
	responsePublicHeader := PublicHeader{
		ConnectionID: connectionID,
		AnnouncePath: true,
		PacketNumber: 1,
	}
	err := responsePublicHeader.Write(fullReply, protocol.VersionWhatever, pers)
	if err != nil {
		utils.Errorf("error composing announcement packet: %s", err.Error())
	}

	addressParts := strings.Split(address.String(), ":")
	workaroundAddress := addressParts[0] + ":" + addressParts[1]

	packetData := getAnnouncementDataFromString(workaroundAddress)
	fullReply.Write(packetData)
	return fullReply.Bytes()
}

func composeAnnouncement(connectionID protocol.ConnectionID, pers protocol.Perspective) []byte {
	fullReply := &bytes.Buffer{}
	responsePublicHeader := PublicHeader{
		ConnectionID: connectionID,
		AnnouncePath: true,
		PacketNumber: 1,
	}
	err := responsePublicHeader.Write(fullReply, protocol.VersionWhatever, pers)
	if err != nil {
		utils.Errorf("error composing announcement packet: %s", err.Error())
	}

	return fullReply.Bytes()
}
