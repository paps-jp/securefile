package cryptobox

import (
	"fmt"
	"io"
)

// chunkOffset returns the ciphertext byte offset at which chunk index begins.
func chunkOffset(index int64) int64 {
	return headerSize + index*(ChunkSize+TagSize)
}

// OpenAt returns a reader yielding plaintext from plaintext offset off onward.
//
// Because chunks are a fixed plaintext size, the chunk containing off is found
// arithmetically: only that chunk and the ones after it are read and
// decrypted. Serving the tail of a 2 GiB file costs one seek, not a 2 GiB
// decrypt — which is what makes HTTP Range requests (and therefore resumable
// downloads and media seeking) practical on encrypted storage.
func OpenAt(src io.ReadSeeker, key []byte, off int64) (io.Reader, error) {
	if off < 0 {
		return nil, fmt.Errorf("cryptobox: negative offset %d", off)
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("cryptobox: seek to header: %w", err)
	}
	h := make([]byte, headerSize)
	if _, err := io.ReadFull(src, h); err != nil {
		return nil, fmt.Errorf("cryptobox: read header: %w", err)
	}
	if string(h[:4]) != string(magic[:]) || h[4] != formatVersion {
		return nil, ErrCorrupt
	}

	index := off / ChunkSize
	within := off % ChunkSize
	if _, err := src.Seek(chunkOffset(index), io.SeekStart); err != nil {
		return nil, fmt.Errorf("cryptobox: seek to chunk %d: %w", index, err)
	}

	r := &Reader{
		aead:   aead,
		src:    src,
		prefix: h[5:headerSize],
		in:     make([]byte, ChunkSize+TagSize),
		index:  uint32(index),
	}
	// Drop the part of the containing chunk that precedes off. Authentication
	// still covers the whole chunk, so a tampered prefix is caught here rather
	// than silently skipped.
	if within > 0 {
		if _, err := io.CopyN(io.Discard, r, within); err != nil {
			if err == io.EOF {
				return nil, fmt.Errorf("cryptobox: offset %d past end of stream", off)
			}
			return nil, err
		}
	}
	return r, nil
}
