package service

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"path"
	"strings"
)

// WriteArchive streams every file in a ticket's share as a ZIP.
//
// The archive is written straight to w as it is produced, so a multi-gigabyte
// share never lands in memory or in a temporary file — which is what makes
// "download everything" usable on a small container.
func (s *Service) WriteArchive(ctx context.Context, ticketID string, w io.Writer) error {
	token, fileID, err := s.redeem(ticketID)
	if err != nil {
		return err
	}
	if fileID != ZipTicket {
		return ErrInvalid
	}
	un, err := s.SessionFiles(ctx, token)
	if err != nil {
		return err
	}

	zw := zip.NewWriter(w)
	used := make(map[string]int, len(un.Files))
	for _, f := range un.Files {
		name := uniqueEntryName(used, SafeFileName(f.Name))
		// Stored, not deflated: the bytes came out of AES and will not
		// compress, so deflate would burn CPU for nothing.
		entry, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			return fmt.Errorf("service: zip entry %q: %w", name, err)
		}
		r, _, err := s.OpenFile(ctx, token, f.ID, 0)
		if err != nil {
			return err
		}
		_, err = io.Copy(entry, r)
		r.Close()
		if err != nil {
			return fmt.Errorf("service: zip copy %q: %w", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("service: close zip: %w", err)
	}
	return nil
}

// SafeFileName reduces a user-supplied name to something safe to write to a
// filesystem or put in a Content-Disposition header.
//
// Names come back from the encrypted metadata exactly as the uploader's
// browser reported them, so they may contain path separators, traversal
// segments, or control characters. Everything here is about making sure the
// recipient's ZIP tool writes a file inside the directory they chose.
func SafeFileName(name string) string {
	// Take the last path element under either separator convention.
	name = strings.ReplaceAll(name, "\\", "/")
	name = path.Base(name)

	name = strings.Map(func(r rune) rune {
		switch {
		case r < 0x20 || r == 0x7f:
			return -1 // control characters
		case strings.ContainsRune(`<>:"|?*`, r):
			return '_' // reserved on Windows
		default:
			return r
		}
	}, name)

	name = strings.Trim(name, " .")
	if name == "" || name == "." || name == ".." {
		return "file"
	}
	// Keep the whole name well inside the 255-byte limit most filesystems use.
	if len(name) > 200 {
		ext := path.Ext(name)
		if len(ext) > 20 {
			ext = ""
		}
		name = name[:200-len(ext)] + ext
	}
	return name
}

// uniqueEntryName appends a counter when a share holds two files with the same
// name, so neither silently overwrites the other on extraction.
func uniqueEntryName(used map[string]int, name string) string {
	n, seen := used[name]
	used[name] = n + 1
	if !seen {
		return name
	}
	ext := path.Ext(name)
	return fmt.Sprintf("%s (%d)%s", strings.TrimSuffix(name, ext), n+1, ext)
}
