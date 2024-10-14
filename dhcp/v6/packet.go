package v6

import "net"

type CliPacket struct {
	MsgType uint8
	TxnID   uint32 //24
	Opts    []byte
}

type RelayPacket struct {
	MsgType  uint8
	HopCount uint8
	LinkAddr net.IP
	PeerAddr net.IP
	Opts     []byte
}
