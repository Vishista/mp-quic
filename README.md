# A copy of QUIC-GO, A QUIC implementation in pure Go https://github.com/lucas-clemente/quic-go

The quic-go repository https://github.com/lucas-clemente/quic-go was cloned on 14 June 2017. 
The mpquic extension is based on commit ID 7a49b06c6c05a3c3927c7e6abde47121fe913a0e.

Author of mpquic: Tobias Viernickel

# Multipath QUIC

The mp quic-go extends the quic-go implementation. 
The server is able to discover and listen on available network interfaces.
The client is able to use different network interfaces to connect to different server IP addresses.

## How to start the multipath server?
    go run ./example/main.go [flags]

or 

    go build ./example/main.go 
    ./path/to/compiled/server [flags]

## Server Flags
The description of the different flags: 

    flag.TYPE("FLAG", DEFAULT, "DESCRIPTION")


set different output/log levels:

    flag.Bool("v", false, "verbose")


set the path to the directory of the cert (e.g. fullhchain.pem) and the key (e.g. privkey.pem):

    flag.String("certpath", getBuildDir(), "certificate directory")


set the path of the directory for the provided content which can be requested by client:

    flag.String("www", "./example/web", "www data")


to set up a tcp server, set this true:

    flag.Bool("tcp", false, "also listen on TCP")


set the port:

    flag.String("port", "6121", "port to use")


change the subflow scheduler, to change or see the available schedulers, look at scheduler.go:

    flag.String("sc", "rr", "schedulers:rr mrtt")


change the stream scheduler, to change or see the available schedulers, look at scheduler.go:
    
    flag.String("ssc", "rr", "stream_schedulers:rr prio sprio")


set the initial congestion window size:

    flag.Int("c", 10, "congestion window packet amount")


set the initial flow control window:

    flag.Int("f", 32, "flow control kB")


set the network interfaces to be used, in linux type "ip a" to get the available interface names:

    flag.String("n", "wlan", "network interfaces separated by ,")



go run /example

### Example

    go run /example/main.go -n=enxa0cec818056b,wlp 

The server starts to listen on the IPv4 address of a network interface matching with enxa0cec818056b or wlp.
The remaining parameters obtain their default values.

## How to start the multipath client?
    go run ./example/client/main.go [flags]

or 

    go build ./example/client/main.go 
    ./path/to/compiled/client [flags]
## Client Flags
The description of the different flags:

    flag.TYPE("FLAG", DEFAULT, "DESCRIPTION")

set different output/log levels:

    flag.Bool("v", false, "verbose")

set a delay for the second request provided by the url args (experimental use only):

    flag.Int("d", 0, "delay request")

in case you only have one network interface, you can use this twice for testing reasons:

    flag.Bool("fmp", false, "fake multipath")

set the network interfaces to be used, in linux type "ip a" to get the available interface names:

    flag.String("n", "wlan", "network interfaces separated by ,")

set the additional ip addresses of the server, for the client-server IP mapping see the following section (IP Mapping):

    flag.String("mip", "", "additional remote ips/ports separated by ,")

set the initial congestion window size:

    flag.Int("c", 10, "congestion window packet amount")

set the initial flow control window:

    flag.Int("f", 32, "flow control kB")


set the url for the request, separated by "space" (mandatory):

    urls := flag.Args()
### Example

    go run /example/client/main.go -n=enxa0cec818056b,wlp2s0 -mip=192.168.34.32:6000  https://127.0.0.1:6121/index.html

The client requests the index.html from the server at 127.0.0.1:6121. It uses its network interface enxa0cec818056b to establish the connection.
From the network interface wlp2s0 an additional path to the server ip 192.168.34.32:6000 will be established.
The remaining parameters obtain their default values.

## IP Mapping
Both, the client and the server have a -n flag. This flag is used to set the network interfaces "interfaces" which should be used. 
The IPv4 address corresponding to these network interfaces are obtained automatically.
The IPv4 addresses can be seen using "ip a" in linux terminal or by looking at the server output after start up.


As we are in an multipath environment, paths may be established in various ways.
Let's assume a server and a client with network interfaces S1, S2 and C1, C2 respectively.
Possible paths (denoted as "mesh") can be: S1-C1, S1-C2, S2-C1 and S2-C2.

To enable full flexebility for the  path/mesh establishment, the -mip flag of the client is introduced.
The -mip flag sets additional server ip addresses "serverIPs", which are used by the client, to establish a path.
The mesh is set up by the client by mapping each -n entry to one -mip entry in order.

The paths for the mesh are establish as follows:

    clients interfaces[0] (-n parameter) is used to set up a path to the address provided in the url (arg parameter)

    clients interfaces[n+1] (-n parameter) is used to set up a path to address serverIPs[n] (-mip parameter)


## Example 
starting a server

    go run /example/main.go -n=lo,ethernet1
starting a client

    go run /example/client/main.go -n=lo,wlan1,ethernet1 -mip=192.168.0.135:6121,192.168.0.135:6121  https://127.0.0.1:6121/index.html

The resulting paths are:

    127.0.0.1:6121 - lo(calhost)

    192.168.0.135:6121 - wlan1

    192.168.0.135:6121 - ethernet1


This means that outgoing from the clients wlan1 interface, the server IP 192.168.0.135:6121 is addressed (as additional path).

Outgoing from clients ethernet1, the servers IP 192.168.0.135:6121 ia addressed (as additional path).

Outgoing from clients lo interface, the servers IP 127.0.0.1:6121 (used for connection establishment).

## Additional Notes

### Packet processing and Scheduling:

The main packet processing happens in the session.go.
The sendPacket method looks for all paths with free congestion window. Together with some more information, the packet_packet.go is called and responsible for packet packing.

Therefor it uses the stream and subflow schedulers.
These schedulers themself are defined using the scheduler.go. A schedulerFunctionLambda and a streamSchedulerFunctionLambda is defined to allow the definition of multiple schedulers.

#### Subflow Scheduling:

The subflow schedulers are implemented in individual go files. After adding a scheduler file, their command line -sc argument can be added in the scheduler.go.
Currently all schedulers start packing a packet by adding control frames and retransmission frames.
After that, stream frames are added if the maximum packet size is not exceeded.

The process of adding stream frames is based on the original quic-go implementation and somehow complex.
Let's look at the min_rtt scheduler (scheduler_min_rtt.go)

```go
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
```

Inside the subflow scheduler (scheduler_min_rtt.go) a function fn is defined and given to the stream scheduler. The stream scheduler selects a stream and calls this fn method with the selected stream. Then fn is applied on this stream and pops stream frames (also asking the flow controller at this point). Based on the return value of fn, the stream scheduler continues to select a next stream or stops.
#### Stream Scheduling:

The stream schedulers are implemented in the streams_map.go. After adding a scheduler , their comand line -ssc argument can be added in the scheduler.go. Currently only the default RoundRobinScheduler and some experimental stream prioritizing schedulers are implemented.


### Multipath establishment:
After setting the addresses using -n and -mip, the next interesting part happens in the quic client (client.go in the root directory).

DialAddr establishes the connection from the client to the server. After the successful handshake (Dial method) all additional paths are immediately established.
The AnnounceUDPAddress method composes and sends announcements packets on the new path to be established. For this the clients connection ID and an additional remote address is used.

The session_multipath_manager.go is responsible for managing transport components for the individual paths.

### Security:

To avoid the struggling with certificates, the client is set to skip verification.
See the TLSClientConfig in example/client/main.go

```go
	hclient := &http.Client{
		Transport: h2quic.NewQuicRoundTripper(localIps,  moreRemoteIps, &tls.Config{InsecureSkipVerify: true}),
	}
}
```

## Open issues

-Server can't notify the client about additional entwork interfaces ("add address" feature is missing) 

-Path close is not supported

-Congestion Control uses a decoupled algorithm (Path windows are independent of each other)

-Retransmission of announcement packets

-Delayed or later path announcement

-The pathId is not being transmitted

-Multipath error handling in general

-For security reasons, new paths should have their own initialisation vector/nonce (maybe based on path ID). Reason: if the same data is sent on multiple paths and have coincidentally the same packet number, they look the same on the wire (even though the are encrypted). 

-Stream Schedulers (except for the RoundRobin) are buggy

-Better interaction of Subflow and Stream scheduler needs to be designed and implemented

-IPv6 is not supported

-Implementation is not tested

# Guides --- copied from  https://github.com/lucas-clemente/quic-go

We currently support Go 1.7+.

Installing and updating dependencies:

    go get -t -u ./...

Running tests:

    go test ./...

### Running the example server

Will fullow in the future... 


### QUIC without HTTP/2

Take a look at [this echo example](example/echo/echo.go).

### Using the example client

Will fullow in the future... 

## Usage

### As a server

See the [example server](example/main.go) or try out [Caddy](https://github.com/mholt/caddy) (from version 0.9, [instructions here](https://github.com/mholt/caddy/wiki/QUIC)). Starting a QUIC server is very similar to the standard lib http in go:

```go
http.Handle("/", http.FileServer(http.Dir(wwwDir)))
h2quic.ListenAndServeQUIC("localhost:4242", "/path/to/cert/chain.pem", "/path/to/privkey.pem", nil)
```

### As a client

See the [example client](example/client/main.go). Use a `QuicRoundTripper` as a `Transport` in a `http.Client`.

```go
http.Client{
  Transport: &h2quic.QuicRoundTripper{},
}
```
