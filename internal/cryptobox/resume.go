package cryptobox

import (
	"errors"
	"fmt"
	"io"
)

// ErrUnaligned reports a resume point that is not on a chunk boundary.
var ErrUnaligned = errors.New("cryptobox: ciphertext length is not on a chunk boundary")

// ResumeState describes where an interrupted encryption left off.
type ResumeState struct {
	// NoncePrefix is the per-file prefix read back from the partial file. It
	// must be reused so the resumed chunks keep a unique nonce per chunk.
	NoncePrefix []byte
	// NextIndex is the index of the next chunk to seal.
	NextIndex uint32
	// PlaintextLen is how many plaintext bytes are already stored.
	PlaintextLen int64
}

// InspectPartial reads the header of a partially written ciphertext and works
// out where to resume.
//
// ciphertextLen must land exactly on a chunk boundary, which holds as long as
// every completed upload part was a whole number of chunks. A part that was
// cut mid-chunk leaves an unusable tail, so the caller must truncate back to
// the last boundary before resuming rather than appending to a torn chunk.
func InspectPartial(src io.Reader, ciphertextLen int64) (*ResumeState, error) {
	if ciphertextLen < headerSize {
		return nil, fmt.Errorf("cryptobox: partial file shorter than header (%d bytes)", ciphertextLen)
	}
	h := make([]byte, headerSize)
	if _, err := io.ReadFull(src, h); err != nil {
		return nil, fmt.Errorf("cryptobox: read header: %w", err)
	}
	if string(h[:4]) != string(magic[:]) || h[4] != formatVersion {
		return nil, ErrCorrupt
	}
	body := ciphertextLen - headerSize
	if body%(ChunkSize+TagSize) != 0 {
		return nil, ErrUnaligned
	}
	chunks := body / (ChunkSize + TagSize)
	return &ResumeState{
		NoncePrefix:  h[5:headerSize],
		NextIndex:    uint32(chunks),
		PlaintextLen: chunks * ChunkSize,
	}, nil
}

// AlignDown returns the largest chunk-aligned ciphertext length that is not
// greater than n. Truncating a partial file to this length discards a torn
// trailing chunk and leaves a resumable stream.
func AlignDown(n int64) int64 {
	if n <= headerSize {
		return headerSize
	}
	body := n - headerSize
	return headerSize + (body/(ChunkSize+TagSize))*(ChunkSize+TagSize)
}

// NewResumeWriter continues an interrupted encryption. dst must be positioned
// at the end of the existing ciphertext; the header is not rewritten.
func NewResumeWriter(dst io.Writer, key []byte, st *ResumeState) (*Writer, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(st.NoncePrefix) != noncePrefixSize {
		return nil, fmt.Errorf("cryptobox: nonce prefix must be %d bytes, got %d", noncePrefixSize, len(st.NoncePrefix))
	}
	prefix := make([]byte, noncePrefixSize)
	copy(prefix, st.NoncePrefix)
	return &Writer{
		aead:        aead,
		dst:         dst,
		prefix:      prefix,
		buf:         make([]byte, ChunkSize),
		index:       st.NextIndex,
		wroteHeader: true, // already on disk from the original attempt
	}, nil
}
