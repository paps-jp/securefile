package httpd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/paps-jp/securefile/internal/service"
)

// maxJSONBody caps request bodies for the small JSON endpoints. File bytes
// arrive on the PATCH path, which is not bounded here.
const maxJSONBody = 1 << 20

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status line is already out; there is nothing useful left to say
		// to the client.
		return
	}
}

// fail reports an error to the client without disclosing internals, and logs
// the real cause for the operator.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	// Storage-full gets its own status and a message in the visitor's language,
	// so an uploader can tell "the server is temporarily full" from "my file is
	// too big" and knows it is worth trying again later.
	if errors.Is(err, service.ErrStorageFull) {
		writeJSON(w, http.StatusInsufficientStorage, map[string]string{
			"error": s.i18n.T(s.lang(r), "error.storage_full"),
		})
		return
	}
	status, msg := statusFor(err)
	if status >= 500 {
		s.log.Error("request failed", "path", r.URL.Path, "err", err)
	}
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("%w: %s", service.ErrInvalid, err)
	}
	return nil
}

// uploadToken reads the secret proving the caller started an upload session.
func uploadToken(r *http.Request) string {
	if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
		return strings.TrimPrefix(v, "Bearer ")
	}
	return r.Header.Get("X-Upload-Token")
}

func sessionToken(r *http.Request) string {
	return r.Header.Get("X-Session-Token")
}

// --- upload ---------------------------------------------------------------

type startRequest struct {
	Files []struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	} `json:"files"`
	Days         int    `json:"days"`
	MaxDownloads int    `json:"maxDownloads"`
	Password     string `json:"password"`
	AllowDelete  bool   `json:"allowDelete"`
	Kind         string `json:"kind"`
	Manage       bool   `json:"manage"`
}

func (s *Server) handleStartUpload(w http.ResponseWriter, r *http.Request) {
	if !s.limit.start.allow(s.clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "リクエストが多すぎます。しばらく待ってからお試しください。",
		})
		return
	}

	var req startRequest
	if err := readJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}

	in := service.StartRequest{
		Days:         req.Days,
		MaxDownloads: req.MaxDownloads,
		Password:     req.Password,
		AllowDelete:  req.AllowDelete,
		Kind:         req.Kind,
		Manage:       req.Manage,
		UploaderHash: hashIP(s.opt.IPHashKey, s.clientIP(r)),
		UploaderIP:   s.clientIP(r).String(),
	}
	for _, f := range req.Files {
		in.Files = append(in.Files, service.FileRequest{Name: f.Name, Size: f.Size})
	}

	res, err := s.svc.StartUpload(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	type outFile struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
		Size int64  `json:"size"`
	}
	out := struct {
		Key         string    `json:"key"`
		ShareURL    string    `json:"shareUrl"`
		Password    string    `json:"password"`
		SessionID   string    `json:"sessionId"`
		Token       string    `json:"token"`
		PartSize    int64     `json:"partSize"`
		ExpiresAt   string    `json:"expiresAt"`
		ManageToken string    `json:"manageToken,omitempty"`
		Files       []outFile `json:"files"`
	}{
		Key:         res.Key,
		ShareURL:    s.shareURL(res.Key),
		Password:    res.Password,
		SessionID:   res.SessionID,
		Token:       res.Token,
		PartSize:    res.PartSize,
		ExpiresAt:   res.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		ManageToken: res.ManageToken,
	}
	for _, f := range res.Files {
		out.Files = append(out.Files, outFile{ID: f.ID, Name: f.Name, Size: f.Size})
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handleUploadState(w http.ResponseWriter, r *http.Request) {
	st, err := s.svc.UploadState(r.Context(), r.PathValue("sid"), uploadToken(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type outFile struct {
		ID       int64 `json:"id"`
		Size     int64 `json:"size"`
		Received int64 `json:"received"`
	}
	out := struct {
		Key      string    `json:"key"`
		PartSize int64     `json:"partSize"`
		Files    []outFile `json:"files"`
	}{Key: st.Key, PartSize: st.PartSize}
	for _, f := range st.Files {
		out.Files = append(out.Files, outFile{ID: f.ID, Size: f.Size, Received: f.Received})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleWritePart stores one part of a file.
//
// The offset travels in a header rather than the body so the server can reject
// a misplaced part before reading any of it, and answer with the offset it
// actually expects.
func (s *Server) handleWritePart(w http.ResponseWriter, r *http.Request) {
	fid, err := strconv.ParseInt(r.PathValue("fid"), 10, 64)
	if err != nil {
		s.fail(w, r, fmt.Errorf("%w: bad file id", service.ErrInvalid))
		return
	}
	offset, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || offset < 0 {
		s.fail(w, r, fmt.Errorf("%w: missing or invalid Upload-Offset", service.ErrInvalid))
		return
	}

	received, err := s.svc.WriteParts(r.Context(), r.PathValue("sid"), uploadToken(r), fid, offset, r.Body)
	var mismatch *service.OffsetMismatch
	if errors.As(err, &mismatch) {
		// 409 with the expected offset: the client seeks and continues rather
		// than starting the file over.
		drainBody(r)
		w.Header().Set("Upload-Offset", strconv.FormatInt(mismatch.Expected, 10))
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":    "オフセットが一致しません。サーバの受信済み位置から再開してください。",
			"expected": mismatch.Expected,
		})
		return
	}
	if err != nil {
		drainBody(r)
		s.fail(w, r, err)
		return
	}
	// The success path may also have stopped short — a part longer than the
	// file's remaining bytes, or a duplicate of a part already stored.
	drainBody(r)

	w.Header().Set("Upload-Offset", strconv.FormatInt(received, 10))
	writeJSON(w, http.StatusOK, map[string]int64{"received": received})
}

func (s *Server) handleFinishUpload(w http.ResponseWriter, r *http.Request) {
	drop, err := s.svc.FinishUpload(r.Context(), r.PathValue("sid"), uploadToken(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key":       drop.Key,
		"shareUrl":  s.shareURL(drop.Key),
		"expiresAt": drop.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

func (s *Server) handleCancelUpload(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.CancelUpload(r.Context(), r.PathValue("sid"), uploadToken(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- download -------------------------------------------------------------

func (s *Server) handlePeek(w http.ResponseWriter, r *http.Request) {
	info, err := s.svc.Peek(r.Context(), r.PathValue("key"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key":           info.Key,
		"expiresAt":     info.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		"remaining":     info.Remaining,
		"fileCount":     info.FileCount,
		"totalSize":     info.TotalSize,
		"deleteAllowed": info.DeleteAllowed,
		"kind":          info.Kind,
	})
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if !s.limit.unlock.allow(s.clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "試行回数が多すぎます。1分ほど待ってからお試しください。",
		})
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := readJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}

	un, err := s.svc.Unlock(r.Context(), r.PathValue("key"), req.Password)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, unlockedJSON(un))
}

func (s *Server) handleSessionFiles(w http.ResponseWriter, r *http.Request) {
	un, err := s.svc.SessionFiles(r.Context(), sessionToken(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, unlockedJSON(un))
}

func unlockedJSON(un *service.Unlocked) map[string]any {
	files := make([]map[string]any, 0, len(un.Files))
	for _, f := range un.Files {
		files = append(files, map[string]any{"id": f.ID, "name": f.Name, "size": f.Size})
	}
	return map[string]any{
		"token":         un.Token,
		"expiresAt":     un.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		"files":         files,
		"deleteAllowed": un.DeleteAllowed,
	}
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	s.svc.Lock(sessionToken(r))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleIssueTicket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FileID int64 `json:"fileId"`
		Zip    bool  `json:"zip"`
	}
	if err := readJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}

	fileID := req.FileID
	if req.Zip {
		fileID = service.ZipTicket
	}
	id, expires, err := s.svc.IssueTicket(r.Context(), sessionToken(r), fileID)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	path := "/dl/" + id
	if req.Zip {
		path = "/zip/" + id
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"url":       path,
		"expiresAt": expires.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

// maxDrain bounds how much of an unread request body the server will discard
// in order to answer cleanly on the same connection.
const maxDrain = 32 << 20

// drainBody reads and discards whatever is left of a request body.
//
// When a handler answers without consuming the body — a rejected offset, a
// duplicate part — Go discards only a small amount on its own and then closes
// the connection. For an 8 MiB upload part that means the client sees a reset
// instead of the response, and a 409 whose entire purpose is to say "resume
// from here" never arrives. Draining costs one part's worth of reading and
// turns a dropped connection into a usable answer.
//
// The cap keeps this from becoming a way to make the server read forever: a
// client sending far more than it declared gets its connection closed, which
// is the right answer for one ignoring the limits.
func drainBody(r *http.Request) {
	if r.Body == nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(r.Body, maxDrain))
}

// handleSessionDelete lets a recipient delete a share they unlocked, when the
// uploader allowed it. Authorised by the session token, not the URL.
func (s *Server) handleSessionDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.DeleteBySession(r.Context(), sessionToken(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
