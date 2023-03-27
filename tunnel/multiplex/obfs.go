package multiplex

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const frameHeaderLength = 13

// obfuscate adds multiplexing headers
func obfuscate(f *Frame, buf []byte, payloadOffsetInBuf int) (int, error) {
	payloadLen := len(f.Payload)
	if payloadLen == 0 {
		return 0, errors.New("payload cannot be empty")
	}

	usefulLen := frameHeaderLength + payloadLen
	if len(buf) < usefulLen {
		return 0, errors.New("obfs buffer too small")
	}
	// we do as much in-place as possible to save allocation
	payload := buf[frameHeaderLength : frameHeaderLength+payloadLen]
	if payloadOffsetInBuf != frameHeaderLength {
		// if payload is not at the correct location in buffer
		copy(payload, f.Payload)
	}

	header := buf[:frameHeaderLength]
	binary.LittleEndian.PutUint32(header[0:4], f.StreamID)
	binary.LittleEndian.PutUint64(header[4:12], f.Seq)
	header[12] = f.Closing

	return usefulLen, nil
}

// deobfuscate unmarshall frames
func deobfuscate(f *Frame, in []byte) error {
	if len(in) < frameHeaderLength {
		return fmt.Errorf("input size %v, but it cannot be shorter than %v bytes", len(in), frameHeaderLength)
	}

	header := in[:frameHeaderLength]
	pldWithOverHead := in[frameHeaderLength:] // payload

	streamID := binary.LittleEndian.Uint32(header[0:4])
	seq := binary.LittleEndian.Uint64(header[4:12])
	closing := header[12]

	usefulPayloadLen := len(pldWithOverHead)
	if usefulPayloadLen < 0 || usefulPayloadLen > len(pldWithOverHead) {
		return errors.New("extra length is negative or extra length is greater than total pldWithOverHead length")
	}

	f.StreamID = streamID
	f.Seq = seq
	f.Closing = closing
	f.Payload = pldWithOverHead
	return nil
}
