package console

import (
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/wire"
	"github.com/coder/websocket"
)

const maxDesktopPacket = 8 << 20

// MeshAgent's KVM stream has 16-bit message lengths, with command 27 wrapping
// large image tiles. Normalize these into one complete command per WS message.
func desktopPacket(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	command, size := binary.BigEndian.Uint16(header[:2]), int(binary.BigEndian.Uint16(header[2:]))
	if command == 27 {
		if size != 8 {
			return nil, errors.New("invalid desktop jumbo header")
		}
		var length [4]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return nil, err
		}
		size = int(binary.BigEndian.Uint32(length[:]))
		if size < 8 || size > maxDesktopPacket {
			return nil, errors.New("desktop packet exceeds limit")
		}
		packet := make([]byte, size)
		if _, err := io.ReadFull(r, packet); err != nil {
			return nil, err
		}
		if binary.BigEndian.Uint16(packet[:2]) != 3 {
			return nil, errors.New("only image tiles may use jumbo packets")
		}
		return packet, nil
	}
	if size < 4 {
		return nil, errors.New("invalid desktop length")
	}
	packet := make([]byte, size)
	copy(packet, header[:])
	_, err := io.ReadFull(r, packet[4:])
	return packet, err
}
func (c *Console) desktop(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != c.origin || r.Header.Get("Sec-WebSocket-Protocol") != "rmm-desktop-v1" {
		fail(w, 403, "Desktop origin rejected")
		return
	}
	ctx, cancel := c.operationContext(r)
	defer cancel()
	conn, closeOperation, err := c.agents.OperationAs(ctx, r.PathValue("id"), wire.Operation{Kind: "desktop"}, c.adminID(r))
	if err != nil {
		fail(w, 409, err.Error())
		return
	}
	defer closeOperation()
	if _, err = ready(conn); err != nil {
		fail(w, 409, err.Error())
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"rmm-desktop-v1"}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(64 << 10)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		for {
			kind, data, err := ws.Read(ctx)
			if err != nil {
				return
			}
			if kind != websocket.MessageBinary || len(data) < 4 || len(data) > 65535 || int(binary.BigEndian.Uint16(data[2:4])) != len(data) {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if _, err = conn.Write(data); err != nil {
				return
			}
		}
	}()
	defer func() { cancel(); ws.CloseNow(); <-done }()
	for {
		packet, err := desktopPacket(conn)
		if err != nil {
			return
		}
		if err = ws.Write(ctx, websocket.MessageBinary, packet); err != nil {
			return
		}
	}
}
