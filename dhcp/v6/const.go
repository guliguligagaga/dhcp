package v6

import "time"

const allDhcpRelayAgentsAndServers = "FF02::1:2"

const allDhcpServers = "FF05::1:3"

// dhcp types
const (
	none = iota
	solicit
	advertise
	request
	confirm
	renew
	rebind
	reply
	release
	decline
	reconfigure
	informationRequest
	relayForward
	relayReply
)

// status codes
const (
	success = iota
	unspecFail
	noAddrsAvail
	noBinding
	notOnLink
	useMulticast
)

// Transmission and Retransmission Parameters
const (
	solMaxDelay = time.Second
	solTimeout  = time.Second
	solMaxRt    = 120 * time.Second
	reqTimeout  = time.Second
	reqMaxRt    = 30 * time.Second
	reqMaxRc    = 10
	cnfMaxDelay = time.Second
	cnfTimeout  = time.Second
	cnfMaxRt    = 4 * time.Second
	cnfMaxRd    = 10 * time.Second
	renTimeout  = 10 * time.Second
	renMaxRt    = 600 * time.Second
	rebTimeout  = 10 * time.Second
	rebMaxRt    = 600 * time.Second
	infMaxDelay = time.Second
	infTimeout  = time.Second
	infMaxRt    = 120 * time.Second
	relTimeout  = time.Second
	relMaxRc    = 5
	decTimeout  = time.Second
	decMaxRc    = 5
	recTimeout  = 2 * time.Second
	recMaxRc    = 8
	hopCountLim = 32
)
