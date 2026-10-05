package spec

import (
	"fmt"
	"io"
)

// Container framing for the on-disk sealed units (SPEC.md 7.1, 11.9). A .seg or .dpe
// object is a 4-byte magic, a 1-byte container version, then the STREAM payload. The
// magic and version are framing only and are NOT bound into the AEAD; the file key
// already binds the segment identity by derivation.
var (
	// MagicSeg is the ASCII "DPS1" prefixing a data segment container.
	MagicSeg = [4]byte{0x44, 0x50, 0x53, 0x31}
	// MagicDpe is the ASCII "DPE1" prefixing an encrypted shard manifest container.
	MagicDpe = [4]byte{0x44, 0x50, 0x45, 0x31}
)

// ContainerVersion is the single-byte container version following the magic.
const ContainerVersion byte = 0x01

// ContainerHeaderSize is the byte length of the magic and version header.
const ContainerHeaderSize = 5

// FrameContainer prepends the magic and the container version to a sealed STREAM
// payload.
func FrameContainer(magic [4]byte, payload []byte) []byte {
	out := make([]byte, 0, ContainerHeaderSize+len(payload))
	out = append(out, magic[0], magic[1], magic[2], magic[3], ContainerVersion)
	return append(out, payload...)
}

// UnframeContainerReader validates and consumes the container header from r, returning
// the same reader positioned at the STREAM payload. It is the streamed-segment form of
// UnframeContainer (buffering a whole sealed object to check a 5-byte prefix would
// defeat a bounded-memory read) and applies the identical checks: a short input, a
// wrong magic and an unsupported version are each rejected with the same wording.
func UnframeContainerReader(magic [4]byte, r io.Reader) (io.Reader, error) {
	var hdr [ContainerHeaderSize]byte
	n, err := io.ReadFull(r, hdr[:])
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("container is %d bytes, shorter than the %d-byte header", n, ContainerHeaderSize)
	}
	if err != nil {
		return nil, err
	}
	if hdr[0] != magic[0] || hdr[1] != magic[1] || hdr[2] != magic[2] || hdr[3] != magic[3] {
		return nil, fmt.Errorf("bad container magic %x, want %x", hdr[:4], magic)
	}
	if hdr[4] != ContainerVersion {
		return nil, fmt.Errorf("unsupported container version 0x%02x", hdr[4])
	}
	return r, nil
}

// UnframeContainer validates and strips the container header, returning the STREAM
// payload. It rejects a short input, a wrong magic and an unsupported version.
func UnframeContainer(magic [4]byte, b []byte) ([]byte, error) {
	if len(b) < ContainerHeaderSize {
		return nil, fmt.Errorf("container is %d bytes, shorter than the %d-byte header", len(b), ContainerHeaderSize)
	}
	if b[0] != magic[0] || b[1] != magic[1] || b[2] != magic[2] || b[3] != magic[3] {
		return nil, fmt.Errorf("bad container magic %x, want %x", b[:4], magic)
	}
	if b[4] != ContainerVersion {
		return nil, fmt.Errorf("unsupported container version 0x%02x", b[4])
	}
	return b[ContainerHeaderSize:], nil
}
