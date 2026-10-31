package console

import (
	"context"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/desktop"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/wire"
	"github.com/coder/websocket"
	"golang.org/x/time/rate"
	"net/http"
	"time"
)

func (c *Console) desktop(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != c.origin || r.Header.Get("Sec-WebSocket-Protocol") != "zireael-desktop-v2" {
		fail(w, 403, "Desktop origin rejected")
		return
	}
	ctx, cancel := c.operationContext(r)
	defer cancel()
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"zireael-desktop-v2"}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(desktop.HeaderSize + desktop.MaxControl)
	send := func(p []byte) error {
		sendCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		return ws.Write(sendCtx, websocket.MessageBinary, p)
	}
	failure := func(code, msg string) {
		_ = send(desktop.Packet(desktop.Control{Type: "status", State: "error", Code: code, Message: msg}))
	}
	conn, closeOperation, err := c.agents.OperationAs(ctx, r.PathValue("id"), wire.Operation{Kind: "desktop-v2"}, c.adminID(r))
	if err != nil {
		failure("desktop_busy", "Device is offline or desktop is already in use.")
		return
	}
	defer closeOperation()
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err = ready(conn); err != nil {
		failure("upgrade_required", "Install the new Go agent to use remote desktop.")
		return
	}
	if end, ok := ctx.Deadline(); ok {
		conn.SetReadDeadline(end)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		lim := rate.NewLimiter(240, 480)
		for {
			kind, p, e := ws.Read(ctx)
			if e != nil {
				return
			}
			if kind != websocket.MessageBinary || !lim.Allow() || desktop.Validate(p, true) != nil {
				return
			}
			ctl, e := desktop.ParseControl(p[desktop.HeaderSize:], true)
			if e != nil {
				return
			}
			if ctl.Type == "start" && ctl.Privilege == "elevated" {
				if !c.fresh(r) {
					failure("sign_in_required", "Sign in again before requesting elevated control.")
					return
				}
				if c.store.RecordActiveActor("desktop.elevated:"+r.PathValue("id"), c.adminID(r), time.Now()) != nil {
					return
				}
			}
			deadline := time.Now().Add(10 * time.Second)
			if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
				deadline = end
			}
			conn.SetWriteDeadline(deadline)
			if desktop.Write(conn, p) != nil {
				return
			}
		}
	}()
	defer func() { cancel(); conn.Close(); ws.CloseNow(); <-done }()
	for {
		p, e := desktop.Read(conn, false)
		if e != nil {
			return
		}
		if e = send(p); e != nil {
			return
		}
	}
}
func (c *Console) desktopPage(w http.ResponseWriter, r *http.Request) {
	raw, _ := assets.ReadFile("web/desktop.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(raw)
}
