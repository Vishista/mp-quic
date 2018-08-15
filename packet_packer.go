package quic

import (
	"bytes"
	"errors"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
)

type packedPacket struct {
	number          protocol.PacketNumber
	raw             []byte
	frames          []frames.Frame
	encryptionLevel protocol.EncryptionLevel
}

type packetPacker struct {
	connectionID protocol.ConnectionID
	perspective  protocol.Perspective
	version      protocol.VersionNumber
	cryptoSetup  handshake.CryptoSetup

	connectionParameters handshake.ConnectionParametersManager
	scheduler            SchedulerInterface
}

func newPacketPacker(connectionID protocol.ConnectionID,
	cryptoSetup handshake.CryptoSetup,
	connectionParameters handshake.ConnectionParametersManager,
	perspective protocol.Perspective,
	version protocol.VersionNumber,
	scheduler SchedulerInterface,
) *packetPacker {
	return &packetPacker{
		cryptoSetup:          cryptoSetup,
		connectionID:         connectionID,
		connectionParameters: connectionParameters,
		perspective:          perspective,
		version:              version,
		scheduler:            scheduler,
	}
}

// PackConnectionClose packs a packet that ONLY contains a ConnectionCloseFrame
func (p *packetPacker) PackConnectionClose(ccf *frames.ConnectionCloseFrame, leastUnacked protocol.PacketNumber, packetNumberGenerator *packetNumberGenerator) (*packedPacket, error) {
	// in case the connection is closed, all queued control frames aren't of any use anymore
	// discard them and queue the ConnectionCloseFrame
	p.scheduler.SetConnectionCloseFrame(ccf)
	return p.packPacket(nil, leastUnacked, nil, packetNumberGenerator)
}

//  RetransmitNonForwardSecurePacket retransmits a handshake packet, that was sent with less than forward-secure encryption
func (p *packetPacker) RetransmitNonForwardSecurePacket(stopWaitingFrame *frames.StopWaitingFrame, packet *ackhandler.Packet, packetNumberGenerator *packetNumberGenerator) (*packedPacket, error) {
	if packet.EncryptionLevel == protocol.EncryptionForwardSecure {
		return nil, errors.New("PacketPacker BUG: forward-secure encrypted handshake packets don't need special treatment")
	}
	if stopWaitingFrame == nil {
		return nil, errors.New("PacketPacker BUG: Handshake retransmissions must contain a StopWaitingFrame")
	}
	return p.packPacket(stopWaitingFrame, 0, packet, packetNumberGenerator)
}

func (p *packetPacker) PackMultipathPackets(allowedPaths []int, pathsWithStreamRetransmission []int, smm *sessionMultipathManager) (map[int]*packedPacket, error) {
	//Maybe iterate over all existing paths
	ackFrames := make(map[int]*frames.AckFrame)
	stopWaitingFrames := make(map[int]*frames.StopWaitingFrame)
	publicHeadersLength := make(map[int]protocol.ByteCount)
	publicHeaders := make(map[int]*PublicHeader)

	isCryptoStreamFrame := p.scheduler.IsCryptoStreamFrame()
	var sealer handshake.Sealer
	var encLevel protocol.EncryptionLevel
	if isCryptoStreamFrame {
		encLevel, sealer = p.cryptoSetup.GetSealerForCryptoStream()
	} else {
		encLevel, sealer = p.cryptoSetup.GetSealer()
	}
	//////////////////
	// All data for the scheduler is being collected here
	/////////////////
	//TODO always allow sending retransmissions
	for _, pathId := range allowedPaths {
		ack := smm.receivedPacketHandler(pathId).GetAckFrame()
		packetNumberGenerator := smm.packetNumberGenerator(pathId)
		leastUnacked := smm.sentPacketHandler(pathId).GetLeastUnacked()
		hasAck := false
		if ack != nil {
			ackFrames[pathId] = ack
			hasAck = true
		}
		//check if there is a stream frame to retransmit
		hasRetransmission := false
		for _, retransmitPath := range pathsWithStreamRetransmission {
			if retransmitPath == pathId {
				hasRetransmission = true
			}
		}

		publicHeader := p.getPublicHeader(leastUnacked, encLevel, packetNumberGenerator)
		publicHeaderLength, err := publicHeader.GetLength(p.perspective)
		publicHeaders[pathId] = publicHeader
		publicHeadersLength[pathId] = publicHeaderLength
		if err != nil {
			return nil, err
		}
		if hasAck || hasRetransmission {
			stopWaitingFrame := smm.sentPacketHandler(pathId).GetStopWaitingFrame(hasRetransmission)
			if stopWaitingFrame != nil {
				stopWaitingFrame.PacketNumber = publicHeader.PacketNumber
				stopWaitingFrame.PacketNumberLen = publicHeader.PacketNumberLen
				stopWaitingFrames[pathId] = stopWaitingFrame
			}
		}
	}

	//////////////////
	// The data is given to the scheduler
	/////////////////
	schedulerData := SchedulerAuxiliaryData{}
	schedulerData.AllowedPaths = allowedPaths
	schedulerData.PathsWithRetransmission = pathsWithStreamRetransmission
	schedulerData.AckFramesMap = ackFrames
	schedulerData.StopWaitingFramesMap = stopWaitingFrames
	schedulerData.PublicHeadersLength = publicHeadersLength
	schedulerData.CanSendData = p.canSendData(encLevel)
	var err error
	var payloadFramesMap map[int][]frames.Frame
	if isCryptoStreamFrame {
		payloadFramesMap, err = p.scheduler.ComposeCryptoPayload(schedulerData)
	} else {
		payloadFramesMap, err = p.scheduler.ComposePayloadForSending(schedulerData)
	}
	//here the payloads of the packets are returned
	if err != nil {
		return nil, err
	}
	packetPacketsMap := make(map[int]*packedPacket)
	for pathId, payloadFrames := range payloadFramesMap {
		// Check if we have enough frames to send
		//Don't send out packets that only contain a StopWaitingFrame
		if len(payloadFrames) == 0 || (len(payloadFrames) == 1 && stopWaitingFrames[pathId] != nil) {
			continue
		}

		packetPacketsMap[pathId], err = p.finishPacket(payloadFrames, publicHeaders[pathId], smm.packetNumberGenerator(pathId), sealer, encLevel)
		if err != nil {
			return nil, err
		}
	}
	return packetPacketsMap, nil

}

func (p *packetPacker) packPacket(stopWaitingFrame *frames.StopWaitingFrame, leastUnacked protocol.PacketNumber, handshakePacketToRetransmit *ackhandler.Packet, packetNumberGenerator *packetNumberGenerator) (*packedPacket, error) {
	// handshakePacketToRetransmit is only set for handshake retransmissions
	isHandshakeRetransmission := (handshakePacketToRetransmit != nil)

	var sealer handshake.Sealer
	var encLevel protocol.EncryptionLevel
	var err error

	// TODO(#656): Only do this for the crypto stream
	if isHandshakeRetransmission {
		encLevel = handshakePacketToRetransmit.EncryptionLevel
		sealer, err = p.cryptoSetup.GetSealerWithEncryptionLevel(encLevel)
		if err != nil {
			return nil, err
		}
	} else {
		encLevel, sealer = p.cryptoSetup.GetSealer()
	}

	publicHeader := p.getPublicHeader(leastUnacked, encLevel, packetNumberGenerator)

	if stopWaitingFrame != nil {
		stopWaitingFrame.PacketNumber = publicHeader.PacketNumber
		stopWaitingFrame.PacketNumberLen = publicHeader.PacketNumberLen
	}

	// if we're packing a ConnectionClose, don't add any StreamFrames
	isConnectionClose := p.scheduler.IsConnectionClose()

	var payloadFrames []frames.Frame
	if isHandshakeRetransmission {
		payloadFrames = append(payloadFrames, stopWaitingFrame)
		// don't retransmit Acks and StopWaitings
		for _, f := range handshakePacketToRetransmit.Frames {
			switch f.(type) {
			case *frames.AckFrame:
				continue
			case *frames.StopWaitingFrame:
				continue
			}
			payloadFrames = append(payloadFrames, f)
		}
	} else if isConnectionClose {
		payloadFrames = p.scheduler.GetConnectionCloseFrame()
	} else {
		return nil, errors.New("PackerPacker BUG: packPacket is only called for handshake retransmissions or connection close")
	}

	return p.finishPacket(payloadFrames, publicHeader, packetNumberGenerator, sealer, encLevel)

}

func (p *packetPacker) finishPacket(payloadFrames []frames.Frame, publicHeader *PublicHeader, packetNumberGenerator *packetNumberGenerator, sealer handshake.Sealer, encLevel protocol.EncryptionLevel) (*packedPacket, error) {
	var err error
	// Check if we have enough frames to send
	if len(payloadFrames) == 0 {
		return nil, nil
	}
	// Don't send out packets that only contain a StopWaitingFrame
	if len(payloadFrames) == 1 {
		if _, ok := payloadFrames[0].(*frames.StopWaitingFrame); ok {
			return nil, nil
		}
	}

	raw := getPacketBuffer()
	buffer := bytes.NewBuffer(raw)

	if err = publicHeader.Write(buffer, p.version, p.perspective); err != nil {
		return nil, err
	}

	payloadStartIndex := buffer.Len()

	for _, frame := range payloadFrames {
		err = frame.Write(buffer, p.version)
		if err != nil {
			return nil, err
		}
	}

	if protocol.ByteCount(buffer.Len()+12) > protocol.MaxPacketSize {
		return nil, errors.New("PacketPacker BUG: packet too large")
	}

	raw = raw[0:buffer.Len()]
	_ = sealer(raw[payloadStartIndex:payloadStartIndex], raw[payloadStartIndex:], publicHeader.PacketNumber, raw[:payloadStartIndex])
	raw = raw[0 : buffer.Len()+12]

	num := packetNumberGenerator.Pop()
	if num != publicHeader.PacketNumber {
		return nil, errors.New("packetPacker BUG: Peeked and Popped packet numbers do not match")
	}

	return &packedPacket{
		number:          publicHeader.PacketNumber,
		raw:             raw,
		frames:          payloadFrames,
		encryptionLevel: encLevel,
	}, nil
}

func (p *packetPacker) getPublicHeader(leastUnacked protocol.PacketNumber, encLevel protocol.EncryptionLevel, packetNumberGenerator *packetNumberGenerator) *PublicHeader {
	pnum := packetNumberGenerator.Peek()
	packetNumberLen := protocol.GetPacketNumberLengthForPublicHeader(pnum, leastUnacked)
	publicHeader := &PublicHeader{
		ConnectionID:         p.connectionID,
		PacketNumber:         pnum,
		PacketNumberLen:      packetNumberLen,
		TruncateConnectionID: p.connectionParameters.TruncateConnectionID(),
	}

	if p.perspective == protocol.PerspectiveServer && encLevel == protocol.EncryptionSecure {
		publicHeader.DiversificationNonce = p.cryptoSetup.DiversificationNonce()
	}
	if p.perspective == protocol.PerspectiveClient && encLevel != protocol.EncryptionForwardSecure {
		publicHeader.VersionFlag = true
		publicHeader.VersionNumber = p.version
	}

	return publicHeader
}

func (p *packetPacker) canSendData(encLevel protocol.EncryptionLevel) bool {
	if p.perspective == protocol.PerspectiveClient {
		return encLevel >= protocol.EncryptionSecure
	}
	return encLevel == protocol.EncryptionForwardSecure
}
