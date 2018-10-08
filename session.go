package quic

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Vishista/mp-quic/ackhandler"
	"github.com/Vishista/mp-quic/flowcontrol"
	"github.com/Vishista/mp-quic/frames"
	"github.com/Vishista/mp-quic/handshake"
	"github.com/Vishista/mp-quic/internal/utils"
	"github.com/Vishista/mp-quic/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

type unpacker interface {
	Unpack(publicHeaderBinary []byte, hdr *PublicHeader, data []byte) (*unpackedPacket, error)
}

type receivedPacket struct {
	remoteAddr   net.Addr
	pconn        net.PacketConn
	publicHeader *PublicHeader
	data         []byte
	rcvTime      time.Time
}

var (
	errRstStreamOnInvalidStream   = errors.New("RST_STREAM received for unknown stream")
	errWindowUpdateOnClosedStream = errors.New("WINDOW_UPDATE received for an already closed stream")
)

var (
	newCryptoSetup       = handshake.NewCryptoSetup
	newCryptoSetupClient = handshake.NewCryptoSetupClient
)

type handshakeEvent struct {
	encLevel protocol.EncryptionLevel
	err      error
}

type closeError struct {
	err    error
	remote bool
}

// A Session is a QUIC session
type session struct {
	connectionID protocol.ConnectionID
	perspective  protocol.Perspective
	version      protocol.VersionNumber
	config       *Config

	scheduler SchedulerInterface

	streamsMap *streamsMap

	streamFramer *streamFramer

	flowControlManager flowcontrol.FlowControlManager

	unpacker unpacker
	packer   *packetPacker

	cryptoSetup handshake.CryptoSetup

	receivedPackets  chan *receivedPacket
	sendingScheduled chan SchedulerSendData
	// closeChan is used to notify the run loop that it should terminate.
	closeChan chan closeError
	runClosed chan struct{}
	closeOnce sync.Once

	// when we receive too many undecryptable packets during the handshake, we send a Public reset
	// but only after a time of protocol.PublicResetTimeout has passed
	undecryptablePackets                   []*receivedPacket
	receivedTooManyUndecrytablePacketsTime time.Time

	// this channel is passed to the CryptoSetup and receives the current encryption level
	// it is closed as soon as the handshake is complete
	aeadChanged       <-chan protocol.EncryptionLevel
	handshakeComplete bool
	// will be closed as soon as the handshake completes, and receive any error that might occur until then
	// it is used to block WaitUntilHandshakeComplete()
	handshakeCompleteChan chan error
	// handshakeChan receives handshake events and is closed as soon the handshake completes
	// the receiving end of this channel is passed to the creator of the session
	// it receives at most 3 handshake events: 2 when the encryption level changes, and one error
	handshakeChan chan<- handshakeEvent

	connectionParameters handshake.ConnectionParametersManager

	sessionCreationTime time.Time

	timer *utils.Timer

	smm *sessionMultipathManager

	defaultPathId int
}

var _ Session = &session{}

// newSession makes a new session
func newSession(
	connection connection,
	v protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	sCfg *handshake.ServerConfig,
	config *Config,
	scheduler string,
	streamScheduler string,
) (packetHandler, <-chan handshakeEvent, error) {
	s := &session{
		connectionID: connectionID,
		perspective:  protocol.PerspectiveServer,
		version:      v,
		config:       config,
	}
	return s.setup(connection, sCfg, "", nil, scheduler, streamScheduler)
}

// declare this as a variable, such that we can it mock it in the tests
var newClientSession = func(
	connection connection,
	hostname string,
	v protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	config *Config,
	negotiatedVersions []protocol.VersionNumber,
) (packetHandler, <-chan handshakeEvent, error) {
	s := &session{
		connectionID: connectionID,
		perspective:  protocol.PerspectiveClient,
		version:      v,
		config:       config,
	}
	//TODO if client needs another scheduler, implement it
	clientscheduler := "rr"
	return s.setup(connection, nil, hostname, negotiatedVersions, clientscheduler, clientscheduler)
}

func (s *session) setup(
	connection connection,
	scfg *handshake.ServerConfig,
	hostname string,
	negotiatedVersions []protocol.VersionNumber,
	scheduler string,
	streamScheduler string,
) (packetHandler, <-chan handshakeEvent, error) {
	aeadChanged := make(chan protocol.EncryptionLevel, 2)
	s.aeadChanged = aeadChanged
	handshakeChan := make(chan handshakeEvent, 3)
	s.handshakeChan = handshakeChan
	s.runClosed = make(chan struct{})
	s.handshakeCompleteChan = make(chan error, 1)
	s.receivedPackets = make(chan *receivedPacket, protocol.MaxSessionUnprocessedPackets)
	s.closeChan = make(chan closeError, 1)
	s.sendingScheduled = make(chan SchedulerSendData, 1)
	s.undecryptablePackets = make([]*receivedPacket, 0, protocol.MaxUndecryptablePackets)
	s.defaultPathId = 0
	s.timer = utils.NewTimer()
	s.sessionCreationTime = time.Now()
	s.smm = newSessionMultipathManager(connection)

	s.connectionParameters = handshake.NewConnectionParamatersManager(s.perspective, s.version,
		s.config.MaxReceiveStreamFlowControlWindow, s.config.MaxReceiveConnectionFlowControlWindow)
	s.flowControlManager = flowcontrol.NewFlowControlManager(s.connectionParameters, s.smm.getRttStatsManager())
	s.streamsMap = newStreamsMap(s.newStream, s.perspective, s.connectionParameters)
	s.streamFramer = newStreamFramer(s.streamsMap, s.flowControlManager)
	s.scheduler = NewScheduler(scheduler, streamScheduler, s.streamFramer, s.streamsMap, s.version, s.smm.getRttStatsManager())

	var err error
	if s.perspective == protocol.PerspectiveServer {
		cryptoStream, _ := s.GetOrOpenStream(1)
		_, _ = s.AcceptStream() // don't expose the crypto stream
		verifySourceAddr := func(clientAddr net.Addr, hstk *handshake.STK) bool {
			var stk *STK
			if hstk != nil {
				stk = &STK{remoteAddr: hstk.RemoteAddr, sentTime: hstk.SentTime}
			}
			return s.config.AcceptSTK(clientAddr, stk)
		}
		s.cryptoSetup, err = newCryptoSetup(
			s.connectionID,
			s.smm.remoteAddress(s.defaultPathId),
			s.version,
			scfg,
			cryptoStream,
			s.connectionParameters,
			s.config.Versions,
			verifySourceAddr,
			aeadChanged,
		)
	} else {
		cryptoStream, _ := s.OpenStream()
		s.cryptoSetup, err = newCryptoSetupClient(
			hostname,
			s.connectionID,
			s.version,
			cryptoStream,
			s.config.TLSConfig,
			s.connectionParameters,
			aeadChanged,
			&handshake.TransportParameters{RequestConnectionIDTruncation: s.config.RequestConnectionIDTruncation},
			negotiatedVersions,
		)
	}
	if err != nil {
		return nil, nil, err
	}
	s.packer = newPacketPacker(s.connectionID,
		s.cryptoSetup,
		s.connectionParameters,
		s.perspective,
		s.version,
		s.scheduler,
	)
	s.unpacker = &packetUnpacker{aead: s.cryptoSetup, version: s.version}

	return s, handshakeChan, nil
}

// run the session main loop
func (s *session) run() error {
	// Start the crypto stream handler
	go func() {
		if err := s.cryptoSetup.HandleCryptoStream(); err != nil {
			s.Close(err)
		}
	}()

	var closeErr closeError
	aeadChanged := s.aeadChanged

runLoop:
	for {
		// Close immediately if requested
		select {
		case closeErr = <-s.closeChan:
			break runLoop
		default:
		}

		s.maybeResetTimer()

		select {
		case closeErr = <-s.closeChan:
			break runLoop
		case <-s.timer.Chan():
			s.timer.SetRead()
			// We do all the interesting stuff after the switch statement, so
			// nothing to see here.
		case schedulerSendData := <-s.sendingScheduled:
			s.scheduler.AddSendData(schedulerSendData)
		case p := <-s.receivedPackets:
			err := s.handlePacketImpl(p)
			if err != nil {
				if qErr, ok := err.(*qerr.QuicError); ok && qErr.ErrorCode == qerr.DecryptionFailure {
					s.tryQueueingUndecryptablePacket(p)
					continue
				}
				s.closeLocal(err)
				continue
			}
			// This is a bit unclean, but works properly, since the packet always
			// begins with the public header and we never copy it.
			putPacketBuffer(p.publicHeader.Raw)
		case l, ok := <-aeadChanged:
			if !ok { // the aeadChanged chan was closed. This means that the handshake is completed.
				utils.Infof("Handshake Complete at %s", time.Since((s.sessionCreationTime)).String())
				s.handshakeComplete = true
				aeadChanged = nil // prevent this case from ever being selected again
				close(s.handshakeChan)
				close(s.handshakeCompleteChan)
			} else {
				s.tryDecryptingQueuedPackets()
				s.handshakeChan <- handshakeEvent{encLevel: l}
			}
		}
		now := time.Now()
		s.smm.checkAlarmTimeouts(now)

		if err := s.sendPacket(); err != nil {
			s.closeLocal(err)
		}
		if !s.receivedTooManyUndecrytablePacketsTime.IsZero() && s.receivedTooManyUndecrytablePacketsTime.Add(protocol.PublicResetTimeout).Before(now) && len(s.undecryptablePackets) != 0 {
			s.closeLocal(qerr.Error(qerr.DecryptionFailure, "too many undecryptable packets received"))
		}
		if s.smm.allNetworksIdl(s.idleTimeout(), now) {
			s.closeLocal(qerr.Error(qerr.NetworkIdleTimeout, "No recent network activity."))
		}
		if !s.handshakeComplete && now.Sub(s.sessionCreationTime) >= s.config.HandshakeTimeout {
			s.closeLocal(qerr.Error(qerr.HandshakeTimeout, "Crypto handshake did not complete in time."))
		}
		s.garbageCollectStreams()
	}

	// only send the error the handshakeChan when the handshake is not completed yet
	// otherwise this chan will already be closed
	if !s.handshakeComplete {
		s.handshakeCompleteChan <- closeErr.err
		s.handshakeChan <- handshakeEvent{err: closeErr.err}
	}
	s.handleCloseError(closeErr, s.defaultPathId)
	close(s.runClosed)
	return closeErr.err
}

func (s *session) maybeResetTimer() {
	deadline := s.smm.GetTimerDeadline(s.idleTimeout())
	if !s.handshakeComplete {
		handshakeDeadline := s.sessionCreationTime.Add(s.config.HandshakeTimeout)
		deadline = utils.MinTime(deadline, handshakeDeadline)
	}
	if !s.receivedTooManyUndecrytablePacketsTime.IsZero() {
		deadline = utils.MinTime(deadline, s.receivedTooManyUndecrytablePacketsTime.Add(protocol.PublicResetTimeout))
	}
	s.timer.Reset(deadline)
}

func (s *session) idleTimeout() time.Duration {
	if s.handshakeComplete {
		return s.connectionParameters.GetIdleConnectionStateLifetime()
	}
	return protocol.InitialIdleTimeout
}

func (s *session) handleAnnouncementPacket(p *receivedPacket) (int, error) {
	announcedConnection := &conn{pconn: p.pconn, currentAddr: p.remoteAddr}
	pathId := s.smm.addNewPath(announcedConnection)
	utils.Infof("Additional Path %d Announced.  Address:%s", pathId, p.remoteAddr)
	return pathId, nil
}

func (s *session) handlePacketImpl(p *receivedPacket) error {
	if s.perspective == protocol.PerspectiveClient {
		diversificationNonce := p.publicHeader.DiversificationNonce
		if len(diversificationNonce) > 0 {
			s.cryptoSetup.SetDiversificationNonce(diversificationNonce)
		}
	}
	if p.rcvTime.IsZero() {
		// To simplify testing
		p.rcvTime = time.Now()
	}

	hdr := p.publicHeader
	data := p.data
	var err error

	if hdr.AnnouncePath {
		_, err = s.handleAnnouncementPacket(p)
		return err
	}

	pathId := s.smm.getPathId(p.remoteAddr, p.pconn.LocalAddr())
	if pathId == -1 {
		utils.Infof("Unknown path warning! Remote Address:", p.remoteAddr, " Local Address:", p.pconn.LocalAddr())
		utils.Infof("Assuming new address as additional path")
		pathId, err = s.handleAnnouncementPacket(p)
		if err != nil {
			return err
		}
	}
	s.smm.setLastNetworkActivityTime(pathId, p.rcvTime)

	// Calculate packet number
	hdr.PacketNumber = protocol.InferPacketNumber(
		hdr.PacketNumberLen,
		s.smm.getLargestRcvdPacketNumber(pathId),
		hdr.PacketNumber,
	)

	packet, err := s.unpacker.Unpack(hdr.Raw, hdr, data)
	if utils.Debug() {
		utils.Debugf("IN Reading on path %d packet 0x%x (%d bytes) time: %s", pathId, hdr.PacketNumber, len(data)+len(hdr.Raw), time.Since(s.sessionCreationTime).String())
	}
	// if the decryption failed, this might be a packet sent by an attacker
	// don't update the remote address
	if quicErr, ok := err.(*qerr.QuicError); ok && quicErr.ErrorCode == qerr.DecryptionFailure {
		return err
	}
	if s.perspective == protocol.PerspectiveServer {
		// update the remote address, even if unpacking failed for any other reason than a decryption error
		s.smm.connection(pathId).SetCurrentRemoteAddr(p.remoteAddr)
	}
	if err != nil {
		return err
	}

	s.smm.setLastRcvdPacketNumber(pathId, hdr.PacketNumber)
	// Only do this after decrypting, so we are sure the packet is not attacker-controlled
	s.smm.setLargestRcvdPacketNumber(pathId, utils.MaxPacketNumber(s.smm.getLargestRcvdPacketNumber(pathId), hdr.PacketNumber))

	if err = s.smm.receivedPacketHandler(pathId).ReceivedPacket(hdr.PacketNumber, packet.IsRetransmittable()); err != nil {
		return err
	}

	return s.handleFrames(packet.frames, pathId)
}

func (s *session) handleFrames(fs []frames.Frame, pathId int) error {
	for _, ff := range fs {
		var err error
		frames.LogFrame(ff, false)
		switch frame := ff.(type) {
		case *frames.StreamFrame:
			err = s.handleStreamFrame(frame)
		case *frames.AckFrame:
			err = s.handleAckFrame(frame, pathId)
		case *frames.ConnectionCloseFrame:
			s.close(qerr.Error(frame.ErrorCode, frame.ReasonPhrase), true)
		case *frames.GoawayFrame:
			err = errors.New("unimplemented: handling GOAWAY frames")
		case *frames.StopWaitingFrame:
			err = s.smm.receivedPacketHandler(pathId).ReceivedStopWaiting(frame)
		case *frames.RstStreamFrame:
			err = s.handleRstStreamFrame(frame)
		case *frames.WindowUpdateFrame:
			err = s.handleWindowUpdateFrame(frame)
		case *frames.BlockedFrame:
		case *frames.PingFrame:
		default:
			return errors.New("Session BUG: unexpected frame type")
		}

		if err != nil {
			switch err {
			case ackhandler.ErrDuplicateOrOutOfOrderAck:
				// Can happen e.g. when packets thought missing arrive late
			case errRstStreamOnInvalidStream:
				// Can happen when RST_STREAMs arrive early or late (?)
				utils.Errorf("Ignoring error in session: %s", err.Error())
			case errWindowUpdateOnClosedStream:
				// Can happen when we already sent the last StreamFrame with the FinBit, but the client already sent a WindowUpdate for this Stream
			default:
				return err
			}
		}
	}
	return nil
}

// handlePacket is called by the server with a new packet
func (s *session) handlePacket(p *receivedPacket) {
	// Discard packets once the amount of queued packets is larger than
	// the channel size, protocol.MaxSessionUnprocessedPackets
	select {
	case s.receivedPackets <- p:
	default:
	}
}

func (s *session) handleStreamFrame(frame *frames.StreamFrame) error {
	str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		// Stream is closed and already garbage collected
		// ignore this StreamFrame
		return nil
	}
	return str.AddStreamFrame(frame)
}

func (s *session) handleWindowUpdateFrame(frame *frames.WindowUpdateFrame) error {
	if frame.StreamID != 0 {
		str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
		if err != nil {
			return err
		}
		if str == nil {
			return errWindowUpdateOnClosedStream
		}
	}
	_, err := s.flowControlManager.UpdateWindow(frame.StreamID, frame.ByteOffset)
	return err
}

func (s *session) handleRstStreamFrame(frame *frames.RstStreamFrame) error {
	str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		return errRstStreamOnInvalidStream
	}

	str.RegisterRemoteError(fmt.Errorf("RST_STREAM received with code %d", frame.ErrorCode))
	return s.flowControlManager.ResetStream(frame.StreamID, frame.ByteOffset)
}

func (s *session) handleAckFrame(frame *frames.AckFrame, pathId int) error {
	return s.smm.sentPacketHandler(pathId).ReceivedAck(frame, s.smm.getLastRcvdPacketNumber(pathId), s.smm.getLastNetworkActivityTime(pathId))
}

func (s *session) close(e error, remoteClose bool) {
	s.closeOnce.Do(func() {
		s.closeChan <- closeError{err: e, remote: remoteClose}
	})
}

func (s *session) closeLocal(e error) {
	s.close(e, false)
}

// Close the connection. If err is nil it will be set to qerr.PeerGoingAway.
// It waits until the run loop has stopped before returning
func (s *session) Close(e error) error {
	s.close(e, false)
	<-s.runClosed
	return nil
}

func (s *session) handleCloseError(closeErr closeError, pathId int) error {
	if closeErr.err == nil {
		closeErr.err = qerr.PeerGoingAway
	}

	var quicErr *qerr.QuicError
	var ok bool
	if quicErr, ok = closeErr.err.(*qerr.QuicError); !ok {
		quicErr = qerr.ToQuicError(closeErr.err)
	}
	// Don't log 'normal' reasons
	if quicErr.ErrorCode == qerr.PeerGoingAway || quicErr.ErrorCode == qerr.NetworkIdleTimeout {
		utils.Infof("Closing connection %x", s.connectionID)
	} else {
		utils.Errorf("Closing session with error: %s", closeErr.err.Error())
	}

	s.streamsMap.CloseWithError(quicErr)

	if closeErr.err == errCloseSessionForNewVersion {
		return nil
	}

	// If this is a remote close we're done here
	if closeErr.remote {
		return nil
	}

	if quicErr.ErrorCode == qerr.DecryptionFailure || quicErr == handshake.ErrHOLExperiment {
		return s.sendPublicReset(s.smm.getLastRcvdPacketNumber(pathId), pathId)
	}
	return s.sendConnectionClose(quicErr, pathId)
}

func (s *session) sendPacket() error {
	// Repeatedly try sending until we don't have any more data, or run out of the congestion window
	for {
		allowedPaths := s.smm.getAllowedPaths()

		pathsWithRetransmission := s.smm.getPathsWithRetransmissions()
		var pathWithStreamRetransmission []int
		if len(allowedPaths) == 0 {
			return nil
		}
		//The original implementation sends retransmission even if congested
		/*if len(allowedPaths) == 0 && len(pathsWithRetransmission) == 0 {
			return nil
		}*/

		var controlFrames []frames.Frame

		// get WindowUpdate frames
		// this call triggers the flow controller to increase the flow control windows, if necessary
		windowUpdateFrames := s.getWindowUpdateFrames()
		for _, wuf := range windowUpdateFrames {
			controlFrames = append(controlFrames, wuf)
		}

		// check for retransmissions first
		for _, pathId := range pathsWithRetransmission {
			for {
				retransmitPacket := s.smm.sentPacketHandler(pathId).DequeuePacketForRetransmission()
				if retransmitPacket == nil {
					break
				}
				utils.Debugf("\tDequeueing retransmission for packet 0x%x on path %d", retransmitPacket.PacketNumber, pathId)

				if retransmitPacket.EncryptionLevel != protocol.EncryptionForwardSecure {
					utils.Debugf("\tDequeueing handshake retransmission for packet 0x%x", retransmitPacket.PacketNumber)
					stopWaitingFrame := s.smm.sentPacketHandler(pathId).GetStopWaitingFrame(true)
					var packet *packedPacket
					packet, err := s.packer.RetransmitNonForwardSecurePacket(stopWaitingFrame, retransmitPacket, s.smm.packetNumberGenerator(pathId))
					if err != nil {
						return err
					}
					if packet == nil {
						continue
					}
					err = s.sendPackedPacket(packet, pathId)
					if err != nil {
						return err
					}
					continue
				} else {
					hasStreamRetransmission := false
					// resend the frames that were in the packet
					for _, frame := range retransmitPacket.GetFramesForRetransmission() {
						switch frame.(type) {
						case *frames.StreamFrame:
							s.streamFramer.AddFrameForRetransmission(frame.(*frames.StreamFrame))
							hasStreamRetransmission = true
						case *frames.WindowUpdateFrame:
							// only retransmit WindowUpdates if the stream is not yet closed and the we haven't sent another WindowUpdate with a higher ByteOffset for the stream
							var currentOffset protocol.ByteCount
							f := frame.(*frames.WindowUpdateFrame)
							currentOffset, err := s.flowControlManager.GetReceiveWindow(f.StreamID)
							if err == nil && f.ByteOffset >= currentOffset {
								controlFrames = append(controlFrames, frame)
							}
						default:
							//Maybe make it path dependend? in case of ack frame?
							controlFrames = append(controlFrames, frame)
						}
					}
					if hasStreamRetransmission {
						pathWithStreamRetransmission = append(pathWithStreamRetransmission, pathId)
					}
				}
			}
		}
		s.scheduler.AddControlFrames(controlFrames)

		packets, err := s.packer.PackMultipathPackets(allowedPaths, pathWithStreamRetransmission, s.smm)
		if err != nil {
			return err
		}
		if len(packets) == 0 {
			return nil
		}
		// send every window update twice
		for _, f := range windowUpdateFrames {
			s.scheduler.QueueControlFrameForNextPacket(f)
		}

		for pathId, packet := range packets {
			err := s.sendPackedPacket(packet, pathId)
			if err != nil {
				return err
			}
			s.smm.setNextAckScheduledTime(pathId, time.Time{})
		}
	}
}

func (s *session) sendPackedPacket(packet *packedPacket, pathId int) error {
	err := s.smm.sentPacketHandler(pathId).SentPacket(&ackhandler.Packet{
		PacketNumber:    packet.number,
		Frames:          packet.frames,
		Length:          protocol.ByteCount(len(packet.raw)),
		EncryptionLevel: packet.encryptionLevel,
	})
	if err != nil {
		return err
	}

	s.logPacket(packet, pathId)
	err = s.smm.Write(packet.raw, pathId)
	putPacketBuffer(packet.raw)
	return err
}

func (s *session) sendConnectionClose(quicErr *qerr.QuicError, pathId int) error {
	//send always on path 0, assuming no path close possible
	packet, err := s.packer.PackConnectionClose(&frames.ConnectionCloseFrame{ErrorCode: quicErr.ErrorCode, ReasonPhrase: quicErr.ErrorMessage}, s.smm.sentPacketHandler(pathId).GetLeastUnacked(), s.smm.packetNumberGenerator(pathId))
	if err != nil {
		return err
	}
	if packet == nil {
		return errors.New("Session BUG: expected packet not to be nil")
	}
	s.logPacket(packet, pathId)
	return s.smm.Write(packet.raw, pathId)
}

func (s *session) logPacket(packet *packedPacket, pathId int) {
	if !utils.Debug() {
		// We don't need to allocate the slices for calling the format functions
		return
	}
	if utils.Debug() {
		utils.Debugf("OUT: Sending on path %d packet 0x%x (%d bytes) time: %s", pathId, packet.number, len(packet.raw), time.Since(s.sessionCreationTime).String())
		for _, frame := range packet.frames {
			frames.LogFrame(frame, true)
		}
	}
}

// GetOrOpenStream either returns an existing stream, a newly opened stream, or nil if a stream with the provided ID is already closed.
// Newly opened streams should only originate from the client. To open a stream from the server, OpenStream should be used.
func (s *session) GetOrOpenStream(id protocol.StreamID) (Stream, error) {
	str, err := s.streamsMap.GetOrOpenStream(id)
	if str != nil {
		return str, err
	}
	// make sure to return an actual nil value here, not an Stream with value nil
	return nil, err
}

// AcceptStream returns the next stream openend by the peer
func (s *session) AcceptStream() (Stream, error) {
	return s.streamsMap.AcceptStream()
}

//SetStreamPriority
func (s *session) SetStreamPriority(priority protocol.PriorityParam, id protocol.StreamID) error {
	//utils.Infof("SetStreamPriority for Stream %d: depends on Stream %d with a weight of %d", id, priority.StreamDep, priority.Weight)
	stream, err := s.GetOrOpenStream(id)
	if err != nil {
		return err
	}
	stream.SetPriority(priority)
	return nil
}

// OpenStream opens a stream
func (s *session) OpenStream() (Stream, error) {
	return s.streamsMap.OpenStream()
}

func (s *session) OpenStreamSync() (Stream, error) {
	return s.streamsMap.OpenStreamSync()
}

func (s *session) WaitUntilHandshakeComplete() error {
	return <-s.handshakeCompleteChan
}

func (s *session) queueResetStreamFrame(id protocol.StreamID, offset protocol.ByteCount) {
	s.scheduler.QueueControlFrameForNextPacket(&frames.RstStreamFrame{
		StreamID:   id,
		ByteOffset: offset,
	})
	s.scheduleSending(SchedulerSendData{
		StreamId:       id,
		Priority:       protocol.PriorityParam{},
		DataByteLength: 0,
	})
}

func (s *session) newStream(id protocol.StreamID) *stream {
	// TODO: find a better solution for determining which streams contribute to connection level flow control
	if id == 1 || id == 3 {
		s.flowControlManager.NewStream(id, false)
	} else {
		s.flowControlManager.NewStream(id, true)
	}
	return newStream(id, s.scheduleSending, s.queueResetStreamFrame, s.flowControlManager)
}

// garbageCollectStreams goes through all streams and removes EOF'ed streams
// from the streams map.
func (s *session) garbageCollectStreams() {
	s.streamsMap.Iterate(func(str *stream) (bool, error) {
		id := str.StreamID()
		if str.finished() {
			err := s.streamsMap.RemoveStream(id)
			if err != nil {
				return false, err
			}
			s.flowControlManager.RemoveStream(id)
		}
		return true, nil
	})
}

func (s *session) sendPublicReset(rejectedPacketNumber protocol.PacketNumber, pathId int) error {
	utils.Infof("Sending public reset for connection %x, packet number %d", s.connectionID, rejectedPacketNumber)
	return s.smm.Write(writePublicReset(s.connectionID, rejectedPacketNumber, 0), pathId)
}

// scheduleSending signals that we have data for sending
func (s *session) scheduleSending(schedulerSendData SchedulerSendData) {
	select {
	case s.sendingScheduled <- schedulerSendData:
	default:
	}
}

func (s *session) tryQueueingUndecryptablePacket(p *receivedPacket) {
	if s.handshakeComplete {
		return
	}
	if len(s.undecryptablePackets)+1 > protocol.MaxUndecryptablePackets {
		// if this is the first time the undecryptablePackets runs full, start the timer to send a Public Reset
		if s.receivedTooManyUndecrytablePacketsTime.IsZero() {
			s.receivedTooManyUndecrytablePacketsTime = time.Now()
			s.maybeResetTimer()
		}
		utils.Infof("Dropping undecrytable packet 0x%x (undecryptable packet queue full)", p.publicHeader.PacketNumber)
		return
	}
	utils.Infof("Queueing packet 0x%x for later decryption", p.publicHeader.PacketNumber)
	s.undecryptablePackets = append(s.undecryptablePackets, p)
}

func (s *session) tryDecryptingQueuedPackets() {
	for _, p := range s.undecryptablePackets {
		s.handlePacket(p)
	}
	s.undecryptablePackets = s.undecryptablePackets[:0]
}

func (s *session) getWindowUpdateFrames() []*frames.WindowUpdateFrame {
	updates := s.flowControlManager.GetWindowUpdates()
	res := make([]*frames.WindowUpdateFrame, len(updates))
	for i, u := range updates {
		res[i] = &frames.WindowUpdateFrame{StreamID: u.StreamID, ByteOffset: u.Offset}
	}
	return res
}

func (s *session) ackAlarmChanged(t time.Time, pathId int) {
	s.smm.setNextAckScheduledTime(pathId, t)
	s.maybeResetTimer()
}

func (s *session) LocalAddr() net.Addr {
	return s.smm.connection(s.defaultPathId).LocalAddr()
}

// RemoteAddr returns the net.Addr of the client
func (s *session) RemoteAddr() net.Addr {
	//TODO maybe make path dependent?
	return s.smm.connection(s.defaultPathId).RemoteAddr()
}
