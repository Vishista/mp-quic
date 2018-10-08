package quic

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Vishista/mp-quic/internal/utils"
	"github.com/Vishista/mp-quic/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

type client struct {
	mutex     sync.Mutex
	listenErr error

	connections []connection
	hostname    string

	errorChan     chan struct{}
	handshakeChan <-chan handshakeEvent

	config            *Config
	versionNegotiated bool // has version negotiation completed yet

	connectionID protocol.ConnectionID
	version      protocol.VersionNumber

	session packetHandler
}

var (
	errCloseSessionForNewVersion = errors.New("closing session in order to recreate it with a new version")
)

// DialAddr establishes a new QUIC connection to a server.
// The hostname for SNI is taken from the given address.
// This implementation also announces an additional local UDP Address
func DialAddr(addr string, config *Config, localAddrs []string, moreRemoteIps []string) (Session, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	localUdpAddr, err := net.ResolveUDPAddr("udp4", localAddrs[0]+":0")
	udpConn, err := net.ListenUDP("udp", localUdpAddr)
	if err != nil {
		return nil, err
	}
	c, sess, err := Dial(udpConn, udpAddr, addr, config)
	if err != nil {
		return sess, err
	}
	//important
	//the first network interface (-n flag) is used to connect to the url given in urls := flag.Args()
	//further network interfaces are mapped to additional ips (-mip flag)
	for i, address := range moreRemoteIps {
		remUdpAddr, _ := net.ResolveUDPAddr("udp4", address)
		localUdpAddr, _ := net.ResolveUDPAddr("udp4", localAddrs[i+1]+":0")
		err = AnnounceUDPAddress(c, remUdpAddr, localUdpAddr)
	}
	/*for _, address := range localAddrs {
		if(address == "192.168.1.241"){
			udpAddr2, _ := net.ResolveUDPAddr("udp4", "192.168.2.242:6121")
			err = AnnounceUDPAddress(c, udpAddr2, address)
		}
		if(address == "192.168.3.241") {
			udpAddr2, _ := net.ResolveUDPAddr("udp4", "192.168.3.242:6121")
			err = AnnounceUDPAddress(c, udpAddr2, address)
		}
		if(address == "10.3.0.241"){
			udpAddr2, _ := net.ResolveUDPAddr("udp4", "10.3.0.242:6121")
			err = AnnounceUDPAddress(c, udpAddr2, address)

		}
	}*/

	return sess, err
}

// Announces an additional local UDP Address
func AnnounceUDPAddress(c *client, remoteAddr net.Addr, localAddr *net.UDPAddr) error {
	//We start Listening on an additional address even before we send the Announcement
	udpConn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return err
	}
	//newRemoteAddr, err := net.ResolveUDPAddr("udp4", localAddr[:2]+remoteAddr.String()[2:])
	newRemoteAddr := remoteAddr
	newConn := &conn{pconn: udpConn, currentAddr: newRemoteAddr}
	c.connections = append(c.connections, newConn)
	go c.listen(len(c.connections) - 1)
	utils.Infof("Announcing additional Path from %s", localAddr)
	utils.Infof("Announcing additional Path to %s", newRemoteAddr)
	//In case you have a lossy environment, sending your announcement multiple times does not harm! (For prototyping reasons)
	err = newConn.Write(composeAnnouncement(c.connectionID, protocol.PerspectiveClient))
	//err = newConn.Write(composeAnnouncement(c.connectionID, protocol.PerspectiveClient))
	//err = newConn.Write(composeAnnouncement(c.connectionID, protocol.PerspectiveClient))
	//err = newConn.Write(composeAnnouncement(c.connectionID, protocol.PerspectiveClient))
	//err = newConn.Write(composeAnnouncement(c.connectionID, protocol.PerspectiveClient))
	return err
}

// DialAddrNonFWSecure establishes a new QUIC connection to a server.
// The hostname for SNI is taken from the given address.
func DialAddrNonFWSecure(addr string, config *Config) (NonFWSession, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	_, sess, err := DialNonFWSecure(udpConn, udpAddr, addr, config)
	return sess, err
}

// DialNonFWSecure establishes a new non-forward-secure QUIC connection to a server using a net.PacketConn.
// The host parameter is used for SNI.
func DialNonFWSecure(pconn net.PacketConn, remoteAddr net.Addr, host string, config *Config) (*client, NonFWSession, error) {
	connID, err := utils.GenerateConnectionID()
	if err != nil {
		return &client{}, nil, err
	}

	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return &client{}, nil, err
	}

	clientConfig := populateClientConfig(config)
	connections := make([]connection, 1)
	connections[0] = &conn{pconn: pconn, currentAddr: remoteAddr}
	c := &client{
		connections:  connections,
		connectionID: connID,
		hostname:     hostname,
		config:       clientConfig,
		version:      clientConfig.Versions[0],
		errorChan:    make(chan struct{}),
	}

	err = c.createNewSession(nil)
	if err != nil {
		return c, nil, err
	}

	utils.Infof("Starting new connection to %s (%s), connectionID %x, version %d", hostname, c.connections[0].RemoteAddr().String(), c.connectionID, c.version)

	return c, c.session.(NonFWSession), c.establishSecureConnection()
}

// Dial establishes a new QUIC connection to a server using a net.PacketConn.
// The host parameter is used for SNI.
func Dial(pconn net.PacketConn, remoteAddr net.Addr, host string, config *Config) (*client, Session, error) {
	c, sess, err := DialNonFWSecure(pconn, remoteAddr, host, config)
	if err != nil {
		return c, nil, err
	}
	err = sess.WaitUntilHandshakeComplete()
	if err != nil {
		return c, nil, err
	}
	return c, sess, nil
}

func populateClientConfig(config *Config) *Config {
	versions := config.Versions
	if len(versions) == 0 {
		versions = protocol.SupportedVersions
	}

	handshakeTimeout := protocol.DefaultHandshakeTimeout
	if config.HandshakeTimeout != 0 {
		handshakeTimeout = config.HandshakeTimeout
	}

	maxReceiveStreamFlowControlWindow := config.MaxReceiveStreamFlowControlWindow
	if maxReceiveStreamFlowControlWindow == 0 {
		maxReceiveStreamFlowControlWindow = protocol.DefaultMaxReceiveStreamFlowControlWindowClient
	}
	maxReceiveConnectionFlowControlWindow := config.MaxReceiveConnectionFlowControlWindow
	if maxReceiveConnectionFlowControlWindow == 0 {
		maxReceiveConnectionFlowControlWindow = protocol.DefaultMaxReceiveConnectionFlowControlWindowClient
	}

	return &Config{
		TLSConfig:                             config.TLSConfig,
		Versions:                              versions,
		HandshakeTimeout:                      handshakeTimeout,
		RequestConnectionIDTruncation:         config.RequestConnectionIDTruncation,
		MaxReceiveStreamFlowControlWindow:     maxReceiveStreamFlowControlWindow,
		MaxReceiveConnectionFlowControlWindow: maxReceiveConnectionFlowControlWindow,
	}
}

// establishSecureConnection returns as soon as the connection is secure (as opposed to forward-secure)
func (c *client) establishSecureConnection() error {
	go c.listen(len(c.connections) - 1)

	select {
	case <-c.errorChan:
		return c.listenErr
	case ev := <-c.handshakeChan:
		if ev.err != nil {
			return ev.err
		}
		if ev.encLevel != protocol.EncryptionSecure {
			return fmt.Errorf("Client BUG: Expected encryption level to be secure, was %s", ev.encLevel)
		}
		return nil
	}
}

// Listen listens
func (c *client) listen(index int) {
	var err error
	pconn := c.connections[index].GetPConn()
	for {
		var n int
		var remoteAddr net.Addr
		data := getPacketBuffer()
		data = data[:protocol.MaxReceivePacketSize]
		// The packet size should not exceed protocol.MaxReceivePacketSize bytes
		// If it does, we only read a truncated packet, which will then end up undecryptable
		n, remoteAddr, err = c.connections[index].Read(data)
		if err != nil {
			if !strings.HasSuffix(err.Error(), "use of closed network connection") {
				c.session.Close(err)
			}
			break
		}
		data = data[:n]
		err = c.handlePacket(remoteAddr, pconn, data)
		if err != nil {
			utils.Errorf("error handling packet: %s", err.Error())
			c.session.Close(err)
			break
		}
	}
}

func (c *client) handlePacket(remoteAddr net.Addr, pconn net.PacketConn, packet []byte) error {
	rcvTime := time.Now()

	r := bytes.NewReader(packet)
	hdr, err := ParsePublicHeader(r, protocol.PerspectiveServer)
	if err != nil {
		return qerr.Error(qerr.InvalidPacketHeader, err.Error())
	}
	hdr.Raw = packet[:len(packet)-r.Len()]

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// ignore delayed / duplicated version negotiation packets
	if c.versionNegotiated && hdr.VersionFlag {
		return nil
	}

	// this is the first packet after the client sent a packet with the VersionFlag set
	// if the server doesn't send a version negotiation packet, it supports the suggested version
	if !hdr.VersionFlag && !c.versionNegotiated {
		c.versionNegotiated = true
	}

	if hdr.VersionFlag {
		// version negotiation packets have no payload
		return c.handlePacketWithVersionFlag(hdr)
	}

	c.session.handlePacket(&receivedPacket{
		remoteAddr:   remoteAddr,
		pconn:        pconn,
		publicHeader: hdr,
		data:         packet[len(packet)-r.Len():],
		rcvTime:      rcvTime,
	})
	return nil
}

func (c *client) handlePacketWithVersionFlag(hdr *PublicHeader) error {
	for _, v := range hdr.SupportedVersions {
		if v == c.version {
			// the version negotiation packet contains the version that we offered
			// this might be a packet sent by an attacker (or by a terribly broken server implementation)
			// ignore it
			return nil
		}
	}

	newVersion := protocol.ChooseSupportedVersion(c.config.Versions, hdr.SupportedVersions)
	if newVersion == protocol.VersionUnsupported {
		return qerr.InvalidVersion
	}

	// switch to negotiated version
	c.version = newVersion
	c.versionNegotiated = true
	var err error
	c.connectionID, err = utils.GenerateConnectionID()
	if err != nil {
		return err
	}
	utils.Infof("Switching to QUIC version %d. New connection ID: %x", newVersion, c.connectionID)

	c.session.Close(errCloseSessionForNewVersion)
	return c.createNewSession(hdr.SupportedVersions)
}

func (c *client) createNewSession(negotiatedVersions []protocol.VersionNumber) error {
	var err error
	//We only give the session the first established connection ([0])
	//This is because all further connections have the same remoteAddress in the current version
	//and a write always uses the same outgoing path (in the current version)
	c.session, c.handshakeChan, err = newClientSession(
		c.connections[0],
		c.hostname,
		c.version,
		c.connectionID,
		c.config,
		negotiatedVersions,
	)
	if err != nil {
		return err
	}

	go func() {
		// session.run() returns as soon as the session is closed
		err := c.session.run()
		if err == errCloseSessionForNewVersion {
			return
		}
		c.listenErr = err
		close(c.errorChan)

		utils.Infof("Connection %x closed.", c.connectionID)
		for _, conn := range c.connections {
			conn.Close()
		}
	}()
	return nil
}
