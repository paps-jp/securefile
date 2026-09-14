package httpd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/paps-jp/securefile/internal/service"
)

// handleDownload streams one file, honouring a single byte range.
//
// Range support is what lets a browser resume a download that was interrupted
// at 90% of a 2 GB file — the old service, which read a whole PHP response,
// made the user start again. Because chunks are fixed size, serving from the
// middle costs a seek rather than a full decrypt.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	ticket := r.PathValue("ticket")

	// Metadata first, which costs nothing: a HEAD request, or a range the
	// client gets wrong, must not spend one of the share's downloads.
	meta, err := s.svc.StatTicket(r.Context(), ticket)
	if err != nil {
		s.failPage(w, r, err)
		return
	}

	start, end, partial, err := parseRange(r.Header.Get("Range"), meta.Size)
	if err != nil {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", meta.Size))
		http.Error(w, "要求された範囲が不正です。", http.StatusRequestedRangeNotSatisfiable)
		return
	}

	length := end - start + 1

	// Open the body before any header is written, so a failure here can still
	// be reported as an error response rather than a truncated download. This
	// is also the call that claims one of the share's downloads, which is why
	// it comes after the HEAD check.
	var body io.ReadCloser
	if r.Method != http.MethodHead {
		body, _, err = s.svc.OpenTicket(r.Context(), ticket, start)
		if err != nil {
			s.failPage(w, r, err)
			return
		}
		defer body.Close()
	}

	h := w.Header()
	// application/octet-stream and an attachment disposition: never let a
	// stored file be rendered as HTML in our own origin.
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", contentDisposition(meta.Name))
	h.Set("Content-Length", strconv.FormatInt(length, 10))
	h.Set("Accept-Ranges", "bytes")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")

	if partial {
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, meta.Size))
		w.WriteHeader(http.StatusPartialContent)
	}
	if r.Method == http.MethodHead {
		return
	}

	if _, err := io.CopyN(w, body, length); err != nil {
		// A client that closes the tab mid-download is ordinary, not an error
		// worth alerting on.
		s.log.Debug("download interrupted", "file", meta.ID, "err", err)
	}
}

// handleArchive streams every file in a share as one ZIP.
func (s *Server) handleArchive(w http.ResponseWriter, r *http.Request) {
	ticket := r.PathValue("ticket")
	if _, _, err := s.svc.TicketSession(ticket); err != nil {
		s.failPage(w, r, err)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Disposition", contentDisposition("securefile.zip"))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")

	if err := s.svc.WriteArchive(r.Context(), ticket, w); err != nil {
		// Headers are already sent, so the transfer just ends short; the
		// client sees a truncated ZIP, which its tooling reports as corrupt.
		s.log.Error("archive failed", "err", err)
	}
}

// parseRange interprets a Range header against a file of the given size.
// It returns the inclusive byte range to send and whether the response is
// partial. An absent or unparseable-but-ignorable header yields the whole file.
func parseRange(header string, size int64) (start, end int64, partial bool, err error) {
	if header == "" {
		return 0, max(size-1, 0), false, nil
	}
	spec, ok := strings.CutPrefix(strings.TrimSpace(header), "bytes=")
	if !ok {
		return 0, 0, false, fmt.Errorf("unsupported range unit")
	}
	// Multiple ranges are legal but rarely used and awkward to serve; one is
	// all a resuming download needs.
	if strings.Contains(spec, ",") {
		return 0, 0, false, fmt.Errorf("multiple ranges are not supported")
	}

	before, after, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, 0, false, fmt.Errorf("malformed range")
	}
	before, after = strings.TrimSpace(before), strings.TrimSpace(after)

	switch {
	case before == "" && after == "":
		return 0, 0, false, fmt.Errorf("empty range")

	case before == "": // suffix range: last N bytes
		n, perr := strconv.ParseInt(after, 10, 64)
		if perr != nil || n <= 0 {
			return 0, 0, false, fmt.Errorf("malformed suffix range")
		}
		if n > size {
			n = size
		}
		return size - n, size - 1, true, nil

	default:
		start, perr := strconv.ParseInt(before, 10, 64)
		if perr != nil || start < 0 || start >= size {
			return 0, 0, false, fmt.Errorf("range start outside file")
		}
		end = size - 1
		if after != "" {
			end, perr = strconv.ParseInt(after, 10, 64)
			if perr != nil || end < start {
				return 0, 0, false, fmt.Errorf("malformed range end")
			}
			end = min(end, size-1)
		}
		return start, end, true, nil
	}
}

// contentDisposition builds a header that works for both ASCII and non-ASCII
// names.
//
// Japanese filenames are the normal case here, and the bare filename parameter
// cannot carry them; the RFC 5987 filename* form can, but older clients ignore
// it. Sending both gives every client something it understands.
func contentDisposition(name string) string {
	safe := service.SafeFileName(name)
	ascii := asciiFallback(safe)
	return fmt.Sprintf("attachment; filename=%q; filename*=UTF-8''%s",
		ascii, url.PathEscape(safe))
}

// asciiFallback replaces characters an older client cannot handle in the plain
// filename parameter.
func asciiFallback(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if strings.Trim(out, "_") == "" {
		return "download"
	}
	return out
}
