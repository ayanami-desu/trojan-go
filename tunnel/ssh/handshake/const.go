package handshake

import "time"

const (
	NonceLen               = 12
	MinPaddingLen          = 128
	MaxPaddingLen          = 255
	EphPubKeyLen           = 32
	SessionIdLen           = 4
	SigLen                 = 64
	MaxClientPacketOneSize = 3 + 3*MaxPaddingLen + SessionIdLen + EphPubKeyLen + NonceLen
	MaxServerPacketOneSize = MaxClientPacketOneSize + SigLen
	MaxPayloadSize         = 1024 * 16
	PayloadOverhead        = 4
	maxWriteChunkSize      = MaxPayloadSize - PayloadOverhead
	baseWriteChunkSize     = 9000
	ReadTimeOut            = 5 * time.Second
)
