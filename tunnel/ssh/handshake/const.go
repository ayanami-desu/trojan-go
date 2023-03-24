package handshake

import "time"

const (
	nonceLen             = 12
	clientPacketHeadSize = 4
	serverPacketHeadSize = 3
	minPaddingLen        = 128
	maxPaddingLen        = 255
	ephPubKeyLen         = 32
	sessionIdLen         = 4
	sigLen               = 64
	maxRandomDataSize    = 3 * maxPaddingLen
	authTagSize          = 16
	maxPayloadSize       = 1024 * 16
	payloadOverhead      = 4
	maxWriteChunkSize    = maxPayloadSize - payloadOverhead
	baseWriteChunkSize   = 9000
	readTimeOut          = 5 * time.Second
)
