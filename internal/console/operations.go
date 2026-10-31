package console

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/wire"
)

// Observe the persisted session without extending its idle expiry. Long-lived
// streams stop within one second of logout, rotation, or expiration.
func (c *Console) operationContext(r *http.Request) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	token := c.sessions.Token(r.Context())
	go func() {
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		for {
			loaded, err := c.sessions.Load(context.Background(), token)
			if err != nil {
				cancel()
				return
			}
			id, decodeErr := base64.RawURLEncoding.DecodeString(c.sessions.GetString(loaded, "adminID"))
			_, adminErr := c.store.Admin(id)
			if decodeErr != nil || adminErr != nil || !c.sessions.GetBool(loaded, "owner") || time.Now().After(c.sessions.Deadline(loaded)) {
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
		}
	}()
	return ctx, cancel
}
func streamDeadline(w http.ResponseWriter) {
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(30 * time.Minute))
	_ = controller.SetWriteDeadline(time.Now().Add(30 * time.Minute))
}
func (c *Console) command(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Script  string `json:"script"`
		Timeout int    `json:"timeout"`
	}
	if decode(r, &input) != nil {
		fail(w, 400, "Invalid command")
		return
	}
	request := wire.Operation{Kind: "command", Script: input.Script, Timeout: input.Timeout}
	if request.Validate() != nil {
		fail(w, 400, "Enter a script up to 32 KiB and a timeout of 1–600 seconds")
		return
	}
	ctx, cancel := c.operationContext(r)
	defer cancel()
	conn, closeOperation, err := c.agents.OperationAs(ctx, r.PathValue("id"), request, c.adminID(r))
	if err != nil {
		fail(w, 409, err.Error())
		return
	}
	defer closeOperation()
	streamDeadline(w)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(200)
	encoder := json.NewEncoder(w)
	flush := http.NewResponseController(w)
	total := 0
	for {
		var result wire.Result
		err = wire.Read(conn, &result)
		if err != nil {
			_ = encoder.Encode(wire.Result{Type: "error", Error: "Command connection ended"})
			return
		}
		total += len(result.Data)
		if total > wire.MaxOutput || len(result.Data) > wire.ChunkSize || (result.Type != "output" && result.Type != "done" && result.Type != "error") {
			_ = encoder.Encode(wire.Result{Type: "error", Error: "Invalid agent command response"})
			return
		}
		if encoder.Encode(result) != nil || flush.Flush() != nil {
			return
		}
		if result.Type != "output" {
			return
		}
	}
}
func ready(conn io.Reader) (wire.Result, error) {
	var result wire.Result
	if err := wire.Read(conn, &result); err != nil {
		return result, errors.New("Agent operation connection ended")
	}
	if result.Type == "error" {
		return result, errors.New(result.Error)
	}
	if result.Type != "ready" || result.Size < 0 || result.Size > wire.MaxFile {
		return result, errors.New("Invalid agent response")
	}
	return result, nil
}
func (c *Console) upload(w http.ResponseWriter, r *http.Request) {
	remotePath, err := url.PathUnescape(r.Header.Get("X-RMM-Path"))
	size, sizeErr := strconv.ParseInt(r.Header.Get("X-RMM-Size"), 10, 64)
	request := wire.Operation{Kind: "upload", Path: remotePath, Size: size}
	if err != nil || sizeErr != nil || request.Validate() != nil || (r.ContentLength >= 0 && r.ContentLength != size) {
		fail(w, 400, "Invalid path or file size (maximum 1 GiB)")
		return
	}
	streamDeadline(w)
	ctx, cancel := c.operationContext(r)
	defer cancel()
	stopBody := context.AfterFunc(ctx, func() { _ = http.NewResponseController(w).SetReadDeadline(time.Now()); _ = r.Body.Close() })
	defer stopBody()
	conn, closeOperation, err := c.agents.OperationAs(ctx, r.PathValue("id"), request, c.adminID(r))
	if err != nil {
		fail(w, 409, err.Error())
		return
	}
	defer closeOperation()
	if _, err = ready(conn); err != nil {
		fail(w, 409, err.Error())
		return
	}
	if _, err = io.CopyN(conn, r.Body, size); err != nil {
		fail(w, 502, "Upload interrupted")
		return
	}
	var extra [1]byte
	if n, err := r.Body.Read(extra[:]); n != 0 || err != io.EOF {
		fail(w, 400, "Incorrect upload size")
		return
	}
	var result wire.Result
	if wire.Read(conn, &result) != nil || result.Type != "done" || result.Size != size {
		fail(w, 502, "Agent did not confirm the complete upload")
		return
	}
	reply(w, 200, map[string]any{"ok": true, "size": size})
}
func (c *Console) download(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Path string `json:"path"`
	}
	if decode(r, &input) != nil {
		fail(w, 400, "Invalid download request")
		return
	}
	request := wire.Operation{Kind: "download", Path: input.Path}
	if request.Validate() != nil {
		fail(w, 400, "Enter an absolute local file path")
		return
	}
	ctx, cancel := c.operationContext(r)
	defer cancel()
	conn, closeOperation, err := c.agents.OperationAs(ctx, r.PathValue("id"), request, c.adminID(r))
	if err != nil {
		fail(w, 409, err.Error())
		return
	}
	defer closeOperation()
	result, err := ready(conn)
	if err != nil {
		fail(w, 409, err.Error())
		return
	}
	streamDeadline(w)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(strings.ReplaceAll(input.Path, "\\", "/"))}))
	w.Header().Set("Content-Length", strconv.FormatInt(result.Size, 10))
	w.WriteHeader(200)
	if _, err = io.CopyN(w, conn, result.Size); err != nil {
		panic(http.ErrAbortHandler)
	}
}
