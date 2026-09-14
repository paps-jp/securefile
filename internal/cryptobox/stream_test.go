package cryptobox

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

func payload(n int) []byte {
	b := make([]byte, n)
	r := rand.New(rand.NewSource(int64(n) + 1))
	r.Read(b)
	return b
}

func seal(t *testing.T, key, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, key)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

var sizes = []int{0, 1, 1000, ChunkSize - 1, ChunkSize, ChunkSize + 1, 2 * ChunkSize, 3*ChunkSize + 7}

func TestRoundTrip(t *testing.T) {
	key := testKey(t)
	for _, n := range sizes {
		plain := payload(n)
		ct := seal(t, key, plain)

		if got, want := int64(len(ct)), CiphertextSize(int64(n)); got != want {
			t.Errorf("size %d: ciphertext is %d bytes, CiphertextSize says %d", n, got, want)
		}

		r, err := NewReader(bytes.NewReader(ct), key)
		if err != nil {
			t.Fatalf("size %d: NewReader: %v", n, err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("size %d: ReadAll: %v", n, err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("size %d: plaintext mismatch (got %d bytes)", n, len(got))
		}
	}
}

// TestWriteInSmallPieces covers the case where a Write lands exactly on a
// chunk boundary and the next Write must still make progress.
func TestWriteInSmallPieces(t *testing.T) {
	key := testKey(t)
	plain := payload(2*ChunkSize + 123)

	var buf bytes.Buffer
	w, err := NewWriter(&buf, key)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for off := 0; off < len(plain); off += 7919 {
		end := min(off+7919, len(plain))
		if _, err := w.Write(plain[off:end]); err != nil {
			t.Fatalf("Write at %d: %v", off, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := NewReader(bytes.NewReader(buf.Bytes()), key)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("plaintext mismatch after piecewise writes")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	ct := seal(t, testKey(t), payload(5000))
	r, err := NewReader(bytes.NewReader(ct), testKey(t))
	if err != nil {
		return // rejected at the header already
	}
	if _, err := io.ReadAll(r); !errors.Is(err, ErrCorrupt) {
		t.Errorf("read with wrong key: got %v, want ErrCorrupt", err)
	}
}

func TestTamperDetected(t *testing.T) {
	key := testKey(t)
	ct := seal(t, key, payload(3*ChunkSize))
	ct[headerSize+10] ^= 0x01

	r, err := NewReader(bytes.NewReader(ct), key)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if _, err := io.ReadAll(r); !errors.Is(err, ErrCorrupt) {
		t.Errorf("read of tampered ciphertext: got %v, want ErrCorrupt", err)
	}
}

// TestTruncationDetected is the property the final-chunk flag exists for: a
// stream cut at a chunk boundary must fail, not decode as a shorter file.
func TestTruncationDetected(t *testing.T) {
	key := testKey(t)
	ct := seal(t, key, payload(3*ChunkSize))
	cut := ct[:headerSize+2*(ChunkSize+TagSize)]

	r, err := NewReader(bytes.NewReader(cut), key)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if _, err := io.ReadAll(r); !errors.Is(err, ErrCorrupt) {
		t.Errorf("read of truncated ciphertext: got %v, want ErrCorrupt", err)
	}
}

func TestOpenAt(t *testing.T) {
	key := testKey(t)
	plain := payload(3*ChunkSize + 4242)
	ct := seal(t, key, plain)

	offsets := []int64{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 500, 2 * ChunkSize, int64(len(plain)) - 1}
	for _, off := range offsets {
		r, err := OpenAt(bytes.NewReader(ct), key, off)
		if err != nil {
			t.Fatalf("OpenAt(%d): %v", off, err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("OpenAt(%d) ReadAll: %v", off, err)
		}
		if !bytes.Equal(got, plain[off:]) {
			t.Errorf("OpenAt(%d): got %d bytes, want %d", off, len(got), len(plain)-int(off))
		}
	}
}

func TestResume(t *testing.T) {
	key := testKey(t)
	plain := payload(3*ChunkSize + 99)
	split := 2 * ChunkSize // resume point must be chunk-aligned

	// First attempt: write the head, then stop without calling Close.
	var buf bytes.Buffer
	w, err := NewWriter(&buf, key)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := w.Write(plain[:split]); err != nil {
		t.Fatalf("Write head: %v", err)
	}
	// Force the buffered whole chunk out without marking end-of-stream.
	if err := w.flush(false); err != nil {
		t.Fatalf("flush: %v", err)
	}
	partial := buf.Bytes()

	st, err := InspectPartial(bytes.NewReader(partial), int64(len(partial)))
	if err != nil {
		t.Fatalf("InspectPartial: %v", err)
	}
	if st.PlaintextLen != int64(split) {
		t.Fatalf("resume point: got %d plaintext bytes, want %d", st.PlaintextLen, split)
	}

	out := bytes.NewBuffer(append([]byte(nil), partial...))
	rw, err := NewResumeWriter(out, key, st)
	if err != nil {
		t.Fatalf("NewResumeWriter: %v", err)
	}
	if _, err := rw.Write(plain[st.PlaintextLen:]); err != nil {
		t.Fatalf("Write tail: %v", err)
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := NewReader(bytes.NewReader(out.Bytes()), key)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("resumed stream does not match original plaintext")
	}
}

func TestAlignDown(t *testing.T) {
	chunk := int64(ChunkSize + TagSize)
	cases := []struct{ in, want int64 }{
		{0, headerSize},
		{headerSize, headerSize},
		{headerSize + 1, headerSize},
		{headerSize + chunk, headerSize + chunk},
		{headerSize + chunk + 5, headerSize + chunk},
		{headerSize + 2*chunk, headerSize + 2*chunk},
	}
	for _, c := range cases {
		if got := AlignDown(c.in); got != c.want {
			t.Errorf("AlignDown(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
