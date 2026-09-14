package httpd_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/paps-jp/securefile/internal/httpd"
	"github.com/paps-jp/securefile/internal/service"
	"github.com/paps-jp/securefile/internal/store"
	"github.com/paps-jp/securefile/web"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()

	st, err := store.Open(t.Context(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := service.DefaultConfig(filepath.Join(dir, "blobs"))
	svc, err := service.New(st, cfg)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}

	h, err := httpd.New(svc, slog.New(slog.DiscardHandler), httpd.Options{
		BaseURL:   "https://up.example.test",
		IPHashKey: []byte("test-key-for-hashing-addresses!!"),
		Assets:    web.Assets,
	})
	if err != nil {
		t.Fatalf("httpd.New: %v", err)
	}

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func decode[T any](t *testing.T, r *http.Response) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	r.Body.Close()
	return v
}

func postJSON(t *testing.T, client *http.Client, url string, payload any, headers map[string]string) *http.Response {
	t.Helper()
	buf, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return res
}

type startResponse struct {
	Key       string `json:"key"`
	ShareURL  string `json:"shareUrl"`
	Password  string `json:"password"`
	SessionID string `json:"sessionId"`
	Token     string `json:"token"`
	PartSize  int64  `json:"partSize"`
	Files     []struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
		Size int64  `json:"size"`
	} `json:"files"`
}

type unlockResponse struct {
	Token string `json:"token"`
	Files []struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
		Size int64  `json:"size"`
	} `json:"files"`
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(int64(n) + 3)).Read(b)
	return b
}

// uploadShare runs the whole upload flow over HTTP and returns the share.
func uploadShare(t *testing.T, srv *httptest.Server, files map[string][]byte, days, maxDownloads int) startResponse {
	t.Helper()
	client := srv.Client()

	type fileSpec struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	}
	var specs []fileSpec
	var order []string
	for name, data := range files {
		specs = append(specs, fileSpec{Name: name, Size: int64(len(data))})
		order = append(order, name)
	}

	res := postJSON(t, client, srv.URL+"/api/uploads", map[string]any{
		"files": specs, "days": days, "maxDownloads": maxDownloads, "password": "",
	}, nil)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("start upload: status %d", res.StatusCode)
	}
	start := decode[startResponse](t, res)

	for i, f := range start.Files {
		data := files[order[i]]
		for off := int64(0); off < int64(len(data)); off += start.PartSize {
			end := min(off+start.PartSize, int64(len(data)))
			url := fmt.Sprintf("%s/api/uploads/%s/files/%d", srv.URL, start.SessionID, f.ID)
			req, err := http.NewRequest(http.MethodPatch, url, bytes.NewReader(data[off:end]))
			if err != nil {
				t.Fatalf("new PATCH: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+start.Token)
			req.Header.Set("Upload-Offset", strconv.FormatInt(off, 10))
			pr, err := client.Do(req)
			if err != nil {
				t.Fatalf("PATCH part: %v", err)
			}
			if pr.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(pr.Body)
				t.Fatalf("PATCH part at %d: status %d: %s", off, pr.StatusCode, body)
			}
			pr.Body.Close()
		}
	}

	fin := postJSON(t, client, fmt.Sprintf("%s/api/uploads/%s/finish", srv.URL, start.SessionID),
		map[string]any{}, map[string]string{"Authorization": "Bearer " + start.Token})
	if fin.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(fin.Body)
		t.Fatalf("finish: status %d: %s", fin.StatusCode, body)
	}
	fin.Body.Close()
	return start
}

func unlock(t *testing.T, srv *httptest.Server, key, password string) unlockResponse {
	t.Helper()
	res := postJSON(t, srv.Client(), srv.URL+"/api/drops/"+key+"/unlock",
		map[string]any{"password": password}, nil)
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("unlock: status %d: %s", res.StatusCode, body)
	}
	return decode[unlockResponse](t, res)
}

func ticketFor(t *testing.T, srv *httptest.Server, token string, payload any) string {
	t.Helper()
	res := postJSON(t, srv.Client(), srv.URL+"/api/session/tickets", payload,
		map[string]string{"X-Session-Token": token})
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("ticket: status %d: %s", res.StatusCode, body)
	}
	out := decode[struct {
		URL string `json:"url"`
	}](t, res)
	return out.URL
}

func TestFullFlowOverHTTP(t *testing.T) {
	srv := newTestServer(t)
	files := map[string][]byte{"議事録.txt": randomBytes(4096)}
	start := uploadShare(t, srv, files, 7, 3)

	if want := "https://up.example.test/" + start.Key; start.ShareURL != want {
		t.Errorf("shareUrl = %q, want %q", start.ShareURL, want)
	}

	// Peek discloses that the share is live, but not what is in it.
	res, err := srv.Client().Get(srv.URL + "/api/drops/" + start.Key)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	peek := decode[map[string]any](t, res)
	if _, leaked := peek["files"]; leaked {
		t.Error("peek response includes file names before a password is given")
	}

	// A wrong password is rejected.
	bad := postJSON(t, srv.Client(), srv.URL+"/api/drops/"+start.Key+"/unlock",
		map[string]any{"password": "definitely-wrong"}, nil)
	if bad.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password: status %d, want 401", bad.StatusCode)
	}
	bad.Body.Close()

	un := unlock(t, srv, start.Key, start.Password)
	if len(un.Files) != 1 || un.Files[0].Name != "議事録.txt" {
		t.Fatalf("unlock returned %+v", un.Files)
	}

	url := ticketFor(t, srv, un.Token, map[string]any{"fileId": un.Files[0].ID})
	dl, err := srv.Client().Get(srv.URL + url)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	defer dl.Body.Close()
	if dl.StatusCode != http.StatusOK {
		t.Fatalf("download: status %d", dl.StatusCode)
	}
	got, err := io.ReadAll(dl.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(got, files["議事録.txt"]) {
		t.Error("downloaded bytes do not match what was uploaded")
	}

	// A Japanese filename has to survive the header round trip.
	cd := dl.Header.Get("Content-Disposition")
	if !strings.Contains(cd, "filename*=UTF-8''") {
		t.Errorf("Content-Disposition lacks an RFC 5987 filename: %q", cd)
	}
	if ct := dl.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
}

// TestRangeRequest covers resuming an interrupted download.
func TestRangeRequest(t *testing.T) {
	srv := newTestServer(t)
	data := randomBytes(300_000)
	start := uploadShare(t, srv, map[string][]byte{"big.bin": data}, 1, 5)
	un := unlock(t, srv, start.Key, start.Password)
	url := srv.URL + ticketFor(t, srv, un.Token, map[string]any{"fileId": un.Files[0].ID})

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Range", "bytes=100000-199999")
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("ranged GET: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusPartialContent {
		t.Fatalf("status %d, want 206", res.StatusCode)
	}
	if want := "bytes 100000-199999/300000"; res.Header.Get("Content-Range") != want {
		t.Errorf("Content-Range = %q, want %q", res.Header.Get("Content-Range"), want)
	}
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, data[100000:200000]) {
		t.Errorf("ranged body: got %d bytes, not the requested range", len(got))
	}

	// An open-ended range, which is what a resuming browser actually sends.
	req2, _ := http.NewRequest(http.MethodGet, url, nil)
	req2.Header.Set("Range", "bytes=250000-")
	res2, err := srv.Client().Do(req2)
	if err != nil {
		t.Fatalf("open range: %v", err)
	}
	defer res2.Body.Close()
	got2, _ := io.ReadAll(res2.Body)
	if !bytes.Equal(got2, data[250000:]) {
		t.Errorf("open range: got %d bytes, want %d", len(got2), len(data)-250000)
	}
}

func TestArchiveDownload(t *testing.T) {
	srv := newTestServer(t)
	files := map[string][]byte{
		"報告.pdf": randomBytes(9000),
		"表.csv":  randomBytes(1500),
	}
	start := uploadShare(t, srv, files, 1, 5)
	un := unlock(t, srv, start.Key, start.Password)
	url := srv.URL + ticketFor(t, srv, un.Token, map[string]any{"zip": true})

	res, err := srv.Client().Get(url)
	if err != nil {
		t.Fatalf("zip GET: %v", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read zip: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	if len(zr.File) != len(files) {
		t.Fatalf("zip holds %d entries, want %d", len(zr.File), len(files))
	}
	for _, entry := range zr.File {
		want, ok := files[entry.Name]
		if !ok {
			t.Errorf("unexpected zip entry %q", entry.Name)
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			t.Fatalf("open entry %q: %v", entry.Name, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read entry %q: %v", entry.Name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("entry %q does not match the uploaded file", entry.Name)
		}
	}
}

// TestResumeOverHTTP checks that a client which lost track of its position is
// told where to continue rather than being made to start over.
func TestResumeOverHTTP(t *testing.T) {
	srv := newTestServer(t)
	client := srv.Client()
	data := randomBytes(3 << 20) // 3 MiB, so parts are whole chunks

	res := postJSON(t, client, srv.URL+"/api/uploads", map[string]any{
		"files":        []map[string]any{{"name": "resume.bin", "size": len(data)}},
		"days":         1,
		"maxDownloads": 1,
	}, nil)
	start := decode[startResponse](t, res)
	fileURL := fmt.Sprintf("%s/api/uploads/%s/files/%d", srv.URL, start.SessionID, start.Files[0].ID)

	send := func(offset int64, chunk []byte) *http.Response {
		req, _ := http.NewRequest(http.MethodPatch, fileURL, bytes.NewReader(chunk))
		req.Header.Set("Authorization", "Bearer "+start.Token)
		req.Header.Set("Upload-Offset", strconv.FormatInt(offset, 10))
		out, err := client.Do(req)
		if err != nil {
			t.Fatalf("PATCH: %v", err)
		}
		return out
	}

	first := send(0, data[:1<<20])
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first part: status %d", first.StatusCode)
	}
	first.Body.Close()

	// Now replay the same part, as a retry after a timeout would.
	replay := send(0, data[:1<<20])
	if replay.StatusCode != http.StatusConflict {
		t.Fatalf("replayed part: status %d, want 409", replay.StatusCode)
	}
	if got := replay.Header.Get("Upload-Offset"); got != "1048576" {
		t.Errorf("conflict Upload-Offset = %q, want 1048576", got)
	}
	replay.Body.Close()

	// Continue from the offset the server reported.
	rest := send(1<<20, data[1<<20:])
	if rest.StatusCode != http.StatusOK {
		t.Fatalf("resumed part: status %d", rest.StatusCode)
	}
	rest.Body.Close()

	fin := postJSON(t, client, fmt.Sprintf("%s/api/uploads/%s/finish", srv.URL, start.SessionID),
		map[string]any{}, map[string]string{"Authorization": "Bearer " + start.Token})
	if fin.StatusCode != http.StatusOK {
		t.Fatalf("finish: status %d", fin.StatusCode)
	}
	fin.Body.Close()

	un := unlock(t, srv, start.Key, start.Password)
	url := srv.URL + ticketFor(t, srv, un.Token, map[string]any{"fileId": un.Files[0].ID})
	dl, err := client.Get(url)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	defer dl.Body.Close()
	got, _ := io.ReadAll(dl.Body)
	if !bytes.Equal(got, data) {
		t.Error("resumed upload did not reproduce the original bytes")
	}
}

// TestUnknownKeyPageIsIndistinguishable checks that probing for valid share
// keys learns nothing from the download page itself.
func TestUnknownKeyPageIsIndistinguishable(t *testing.T) {
	srv := newTestServer(t)
	start := uploadShare(t, srv, map[string][]byte{"a.txt": randomBytes(16)}, 1, 1)

	real, err := srv.Client().Get(srv.URL + "/" + start.Key)
	if err != nil {
		t.Fatalf("GET real key: %v", err)
	}
	realBody, _ := io.ReadAll(real.Body)
	real.Body.Close()

	fake, err := srv.Client().Get(srv.URL + "/zzzzzzzzzzzzzz")
	if err != nil {
		t.Fatalf("GET fake key: %v", err)
	}
	fakeBody, _ := io.ReadAll(fake.Body)
	fake.Body.Close()

	if real.StatusCode != fake.StatusCode {
		t.Errorf("status differs: real %d, fake %d", real.StatusCode, fake.StatusCode)
	}
	// The pages differ only in the key embedded in them.
	normalise := func(b []byte, key string) string {
		return strings.ReplaceAll(string(b), key, "KEY")
	}
	if normalise(realBody, start.Key) != normalise(fakeBody, "zzzzzzzzzzzzzz") {
		t.Error("download page markup differs between a real and an unknown key")
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv := newTestServer(t)
	res, err := srv.Client().Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer res.Body.Close()

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for header, value := range want {
		if got := res.Header.Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}

	csp := res.Header.Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP is missing %q: %s", directive, csp)
		}
	}

	// The page must not reach for anything off-origin.
	body, _ := io.ReadAll(res.Body)
	for _, host := range []string{"googletagmanager", "googlesyndication", "jquery", "http://", "https://"} {
		if host == "https://" {
			// paps.jp in the footer is a link, not a subresource.
			continue
		}
		if bytes.Contains(body, []byte(host)) {
			t.Errorf("index page references %q", host)
		}
	}
}

func TestSessionTokenRequired(t *testing.T) {
	srv := newTestServer(t)
	start := uploadShare(t, srv, map[string][]byte{"a.txt": randomBytes(16)}, 1, 2)
	un := unlock(t, srv, start.Key, start.Password)

	// A ticket request with no session token must be refused.
	res := postJSON(t, srv.Client(), srv.URL+"/api/session/tickets",
		map[string]any{"fileId": un.Files[0].ID}, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("ticket without session token: status %d, want 404", res.StatusCode)
	}
	res.Body.Close()

	// So must an unknown ticket.
	dl, err := srv.Client().Get(srv.URL + "/dl/not-a-real-ticket")
	if err != nil {
		t.Fatalf("GET bad ticket: %v", err)
	}
	defer dl.Body.Close()
	if dl.StatusCode != http.StatusNotFound {
		t.Errorf("unknown ticket: status %d, want 404", dl.StatusCode)
	}
}

// TestHeadDoesNotConsumeADownload guards the case where a download manager
// probes with HEAD before fetching: the probe must not spend the recipient's
// allowance, which for a share limited to one download would mean they never
// get the file at all.
func TestHeadDoesNotConsumeADownload(t *testing.T) {
	srv := newTestServer(t)
	start := uploadShare(t, srv, map[string][]byte{"a.bin": randomBytes(2048)}, 1, 1)
	un := unlock(t, srv, start.Key, start.Password)
	url := srv.URL + ticketFor(t, srv, un.Token, map[string]any{"fileId": un.Files[0].ID})

	remaining := func() float64 {
		res, err := srv.Client().Get(srv.URL + "/api/drops/" + start.Key)
		if err != nil {
			t.Fatalf("peek: %v", err)
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			t.Fatalf("peek: status %d", res.StatusCode)
		}
		return decode[map[string]any](t, res)["remaining"].(float64)
	}

	if got := remaining(); got != 1 {
		t.Fatalf("before any request, remaining = %v, want 1", got)
	}

	head, err := srv.Client().Head(url)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	head.Body.Close()
	if head.StatusCode != http.StatusOK {
		t.Errorf("HEAD: status %d, want 200", head.StatusCode)
	}
	if got := head.Header.Get("Content-Length"); got != "2048" {
		t.Errorf("HEAD Content-Length = %q, want 2048", got)
	}
	if got := remaining(); got != 1 {
		t.Errorf("after HEAD, remaining = %v, want 1 (the probe spent a download)", got)
	}

	// The real transfer does spend it.
	res, err := srv.Client().Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()

	// Exhausted now, so the share reads as gone.
	peek, err := srv.Client().Get(srv.URL + "/api/drops/" + start.Key)
	if err != nil {
		t.Fatalf("peek after transfer: %v", err)
	}
	peek.Body.Close()
	if peek.StatusCode != http.StatusNotFound {
		t.Errorf("after the allowance is spent: status %d, want 404", peek.StatusCode)
	}
}

// TestLargeRejectedPartStillGetsAnAnswer covers the failure that makes a
// resumable upload unresumable: when the server refuses a part without reading
// its body, Go discards only a little of it and then closes the connection, so
// the 409 that carries the resume offset never reaches the client.
func TestLargeRejectedPartStillGetsAnAnswer(t *testing.T) {
	srv := newTestServer(t)
	client := srv.Client()
	data := randomBytes(2 << 20) // well past Go's automatic drain limit

	res := postJSON(t, client, srv.URL+"/api/uploads", map[string]any{
		"files":        []map[string]any{{"name": "drain.bin", "size": len(data)}},
		"days":         1,
		"maxDownloads": 1,
	}, nil)
	start := decode[startResponse](t, res)
	fileURL := fmt.Sprintf("%s/api/uploads/%s/files/%d", srv.URL, start.SessionID, start.Files[0].ID)

	send := func(offset int64, chunk []byte) (*http.Response, error) {
		req, _ := http.NewRequest(http.MethodPatch, fileURL, bytes.NewReader(chunk))
		req.Header.Set("Authorization", "Bearer "+start.Token)
		req.Header.Set("Upload-Offset", strconv.FormatInt(offset, 10))
		return client.Do(req)
	}

	first, err := send(0, data[:1<<20])
	if err != nil {
		t.Fatalf("first part: %v", err)
	}
	first.Body.Close()

	// Replay the whole 1 MiB part at an offset the server has moved past.
	replay, err := send(0, data[:1<<20])
	if err != nil {
		t.Fatalf("replayed part got a transport error instead of a response: %v", err)
	}
	defer replay.Body.Close()

	if replay.StatusCode != http.StatusConflict {
		t.Fatalf("replayed part: status %d, want 409", replay.StatusCode)
	}
	body := decode[map[string]any](t, replay)
	if body["expected"] != float64(1<<20) {
		t.Errorf("409 body expected = %v, want %d", body["expected"], 1<<20)
	}

	// The connection must still be usable, which is the point of draining.
	rest, err := send(1<<20, data[1<<20:])
	if err != nil {
		t.Fatalf("part after a rejection: %v", err)
	}
	rest.Body.Close()
	if rest.StatusCode != http.StatusOK {
		t.Errorf("part after a rejection: status %d, want 200", rest.StatusCode)
	}
}
