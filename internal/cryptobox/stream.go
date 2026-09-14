// Package cryptobox implements the at-rest encryption used by セキュファイル便.
//
// Files are encrypted with the STREAM construction (Hoang et al.): the
// plaintext is split into fixed-size chunks, each sealed independently with
// AES-256-GCM under a nonce derived from a per-file random prefix, the chunk
// index, and a final-chunk flag.
//
// Fixed-size chunks mean chunk N of the ciphertext always lives at a
// computable offset, so a range request can decrypt from the middle of a file
// without touching the chunks before it. The final-chunk flag makes truncation
// detectable: a stream cut short fails to authenticate rather than decoding as
// a shorter file.
package cryptobox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// ChunkSize is the plaintext size of one sealed chunk.
	ChunkSize = 1 << 20 // 1 MiB
	// TagSize is the AES-GCM authentication tag length.
	TagSize = 16
	// KeySize is the length of a data encryption key.
	KeySize = 32

	noncePrefixSize = 7
	nonceSize       = 12 // 7 prefix + 4 counter + 1 final flag
	headerSize      = 12 // magic(4) + version(1) + prefix(7)
	formatVersion   = 1
)

var magic = [4]byte{'S', 'F', 'B', 0x01}

// ErrCorrupt is returned when a chunk fails authentication. It deliberately
// does not distinguish "wrong key" from "tampered ciphertext" from "truncated
// file" — all three are the same answer to the caller: do not trust this data.
var ErrCorrupt = errors.New("cryptobox: ciphertext failed authentication")

// NewKey returns a fresh random data encryption key.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("cryptobox: generate key: %w", err)
	}
	return k, nil
}

func nonce(prefix []byte, index uint32, final bool) []byte {
	n := make([]byte, nonceSize)
	copy(n, prefix)
	binary.BigEndian.PutUint32(n[noncePrefixSize:], index)
	if final {
		n[nonceSize-1] = 1
	}
	return n
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("cryptobox: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptobox: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptobox: new gcm: %w", err)
	}
	return aead, nil
}

// CiphertextSize reports the on-disk size of a plaintext of n bytes.
func CiphertextSize(n int64) int64 {
	chunks := n / ChunkSize
	if rem := n % ChunkSize; rem != 0 || n == 0 {
		chunks++
	}
	return headerSize + n + chunks*TagSize
}

// Writer seals a plaintext stream into an encrypted one. Close must be called
// to flush the final chunk, which also carries the end-of-stream marker.
type Writer struct {
	aead        cipher.AEAD
	dst         io.Writer
	prefix      []byte
	buf         []byte
	n           int
	index       uint32
	wroteHeader bool
	closed      bool
}

// NewWriter returns a Writer that encrypts to dst under key.
func NewWriter(dst io.Writer, key []byte) (*Writer, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, noncePrefixSize)
	if _, err := rand.Read(prefix); err != nil {
		return nil, fmt.Errorf("cryptobox: generate nonce prefix: %w", err)
	}
	return &Writer{
		aead:   aead,
		dst:    dst,
		prefix: prefix,
		buf:    make([]byte, ChunkSize),
	}, nil
}

func (w *Writer) writeHeader() error {
	if w.wroteHeader {
		return nil
	}
	h := make([]byte, 0, headerSize)
	h = append(h, magic[:]...)
	h = append(h, formatVersion)
	h = append(h, w.prefix...)
	if _, err := w.dst.Write(h); err != nil {
		return fmt.Errorf("cryptobox: write header: %w", err)
	}
	w.wroteHeader = true
	return nil
}

// flush seals the buffered chunk. final marks it as the end of the stream.
func (w *Writer) flush(final bool) error {
	if err := w.writeHeader(); err != nil {
		return err
	}
	sealed := w.aead.Seal(nil, nonce(w.prefix, w.index, final), w.buf[:w.n], nil)
	if _, err := w.dst.Write(sealed); err != nil {
		return fmt.Errorf("cryptobox: write chunk %d: %w", w.index, err)
	}
	w.index++
	w.n = 0
	return nil
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("cryptobox: write after close")
	}
	written := 0
	for len(p) > 0 {
		// Flush a full buffer only once we know more data follows, so the last
		// chunk — written by Close — always carries the final flag.
		if w.n == ChunkSize {
			if err := w.flush(false); err != nil {
				return written, err
			}
		}
		n := copy(w.buf[w.n:], p)
		w.n += n
		p = p[n:]
		written += n
	}
	return written, nil
}

// FlushFull seals a whole buffered chunk without marking end-of-stream, so a
// later Writer can pick the stream up where this one stopped.
//
// It is the operation a resumable upload needs between parts: the bytes
// written so far become durable and chunk-aligned, but the stream stays open,
// so an interrupted transfer resumes from the boundary instead of restarting.
// A part that does not land on a chunk boundary is rejected — appending to a
// torn chunk would break both resume and ranged reads.
func (w *Writer) FlushFull() error {
	switch w.n {
	case ChunkSize:
		return w.flush(false)
	case 0:
		// Nothing buffered, but the header still has to exist on disk so a
		// resuming writer can read back the nonce prefix.
		return w.writeHeader()
	default:
		return fmt.Errorf("%w: %d buffered bytes", ErrUnaligned, w.n)
	}
}

// Close seals the trailing chunk with the end-of-stream marker. It does not
// close the underlying writer.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	return w.flush(true)
}

// Reader decrypts a stream produced by Writer.
type Reader struct {
	aead   cipher.AEAD
	src    io.Reader
	prefix []byte
	in     []byte
	out    []byte
	off    int
	index  uint32
	done   bool
}

// NewReader returns a Reader that decrypts src under key. The header is read
// eagerly so a malformed or wrong-format stream fails immediately.
func NewReader(src io.Reader, key []byte) (*Reader, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	h := make([]byte, headerSize)
	if _, err := io.ReadFull(src, h); err != nil {
		return nil, fmt.Errorf("cryptobox: read header: %w", err)
	}
	if string(h[:4]) != string(magic[:]) || h[4] != formatVersion {
		return nil, ErrCorrupt
	}
	return &Reader{
		aead:   aead,
		src:    src,
		prefix: h[5:headerSize],
		in:     make([]byte, ChunkSize+TagSize),
	}, nil
}

// fill decrypts the next chunk into r.out.
func (r *Reader) fill() error {
	n, err := io.ReadFull(r.src, r.in)
	switch {
	case err == nil:
		// A full read may still be the final chunk; try both flags.
	case errors.Is(err, io.ErrUnexpectedEOF):
		// Short read: this must be the final chunk.
	case errors.Is(err, io.EOF):
		// Stream ended on a chunk boundary without a final-flagged chunk.
		return ErrCorrupt
	default:
		return fmt.Errorf("cryptobox: read chunk %d: %w", r.index, err)
	}
	if n < TagSize {
		return ErrCorrupt
	}

	// A full-size read is ambiguous: it may be an interior chunk or an exactly
	// chunk-sized final one. Try interior first, then final.
	if n == len(r.in) {
		out, ferr := r.aead.Open(r.out[:0], nonce(r.prefix, r.index, false), r.in[:n], nil)
		if ferr == nil {
			r.out, r.off, r.index = out, 0, r.index+1
			return nil
		}
	}
	out, ferr := r.aead.Open(r.out[:0], nonce(r.prefix, r.index, true), r.in[:n], nil)
	if ferr != nil {
		return ErrCorrupt
	}
	r.out, r.off, r.index, r.done = out, 0, r.index+1, true
	return nil
}

func (r *Reader) Read(p []byte) (int, error) {
	for r.off >= len(r.out) {
		if r.done {
			return 0, io.EOF
		}
		if err := r.fill(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.out[r.off:])
	r.off += n
	return n, nil
}
