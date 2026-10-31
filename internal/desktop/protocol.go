// Package desktop implements the bounded desktop v2 protocol shared by the
// browser relay and Windows capture worker. It carries no authentication keys.
package desktop

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"golang.org/x/time/rate"
	"image/jpeg"
	"io"
	"net"
	"time"
	"unicode/utf8"
)

const HeaderSize = 12
const MaxControl = 16 << 10
const MaxFrame = 8 << 20
const MaxPixels = 16777216
const Magic = "ZRD2"

var ErrProtocol = errors.New("invalid desktop protocol message")

type Session struct {
	ID     uint32 `json:"id"`
	Label  string `json:"label"`
	Active bool   `json:"active"`
}
type Monitor struct {
	ID       uint32 `json:"id"`
	Label    string `json:"label"`
	X        int32  `json:"x"`
	Y        int32  `json:"y"`
	Width    uint32 `json:"width"`
	Height   uint32 `json:"height"`
	Rotation uint32 `json:"rotation"`
}

func (m Monitor) Valid() bool {
	return m.ID > 0 && len(m.Label) <= 128 && Dimensions(m.Width, m.Height, 16384) && (m.Rotation == 0 || m.Rotation == 90 || m.Rotation == 180 || m.Rotation == 270)
}
func Dimensions(w, h, max uint32) bool {
	return w > 0 && h > 0 && w <= max && h <= max && uint64(w)*uint64(h) <= MaxPixels
}

type Control struct {
	Type              string    `json:"type"`
	Protocol          int       `json:"protocol,omitempty"`
	Sessions          []Session `json:"sessions,omitempty"`
	DefaultSession    *uint32   `json:"defaultSession,omitempty"`
	ElevatedAvailable bool      `json:"elevatedAvailable,omitempty"`
	SessionID         uint32    `json:"sessionID,omitempty"`
	Privilege         string    `json:"privilege,omitempty"`
	ViewOnly          bool      `json:"viewOnly,omitempty"`
	MaxFPS            int       `json:"maxFPS,omitempty"`
	MaxEdge           int       `json:"maxEdge,omitempty"`
	Quality           int       `json:"quality,omitempty"`
	Backend           string    `json:"backend,omitempty"`
	State             string    `json:"state,omitempty"`
	Code              string    `json:"code,omitempty"`
	Message           string    `json:"message,omitempty"`
	Elevated          bool      `json:"elevated,omitempty"`
	Generation        uint32    `json:"generation,omitempty"`
	Monitors          []Monitor `json:"monitors,omitempty"`
	SelectedMonitor   uint32    `json:"selectedMonitor,omitempty"`
	Sequence          uint32    `json:"sequence,omitempty"`
	MonitorID         uint32    `json:"monitorID,omitempty"`
	X                 int32     `json:"x,omitempty"`
	Y                 int32     `json:"y,omitempty"`
	Action            string    `json:"action,omitempty"`
	Button            int       `json:"button,omitempty"`
	Delta             int32     `json:"delta,omitempty"`
	Down              bool      `json:"down,omitempty"`
	Repeat            bool      `json:"repeat,omitempty"`
	Text              string    `json:"text,omitempty"`
	Nonce             uint32    `json:"nonce,omitempty"`
}

var fields = map[string]string{
	"hello": "protocol sessions defaultSession elevatedAvailable", "start": "sessionID privilege viewOnly maxFPS maxEdge quality backend",
	"status": "state code message backend elevated", "geometry": "generation monitors selectedMonitor", "ack": "sequence generation",
	"select-monitor": "monitorID generation", "settings": "viewOnly maxFPS maxEdge quality backend", "pointer": "generation x y action button delta",
	"key": "generation code down repeat", "text": "generation text", "release-input": "", "ping": "nonce", "pong": "nonce", "stop": "",
}

func SettingsValid(c Control) bool {
	return c.MaxFPS >= 1 && c.MaxFPS <= 15 && c.MaxEdge >= 320 && c.MaxEdge <= 2560 && c.Quality >= 40 && c.Quality <= 85 && (c.Backend == "" || c.Backend == "auto" || c.Backend == "gdi")
}
func ParseControl(data []byte, fromViewer bool) (Control, error) {
	var c Control
	if len(data) == 0 || len(data) > MaxControl || !utf8.Valid(data) {
		return c, ErrProtocol
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&c) != nil {
		return c, ErrProtocol
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return c, ErrProtocol
	}
	allowed, ok := fields[c.Type]
	if !ok {
		return c, ErrProtocol
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) != nil {
		return c, ErrProtocol
	}
	for k, v := range obj {
		if k != "type" && !word(allowed, k) {
			return c, ErrProtocol
		}
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return c, ErrProtocol
		}
	}
	if fromViewer && (c.Type == "hello" || c.Type == "status" || c.Type == "geometry") {
		return c, ErrProtocol
	}
	if !fromViewer && c.Type != "hello" && c.Type != "status" && c.Type != "geometry" && c.Type != "ping" && c.Type != "pong" {
		return c, ErrProtocol
	}
	switch c.Type {
	case "hello":
		if c.Protocol != 2 || len(c.Sessions) > 16 {
			return c, ErrProtocol
		}
		seen := map[uint32]bool{}
		for _, s := range c.Sessions {
			if seen[s.ID] || len(s.Label) > 128 {
				return c, ErrProtocol
			}
			seen[s.ID] = true
		}
		if c.DefaultSession != nil && !seen[*c.DefaultSession] {
			return c, ErrProtocol
		}
	case "start":
		if !SettingsValid(c) || (c.Privilege != "user" && c.Privilege != "elevated") {
			return c, ErrProtocol
		}
	case "settings":
		if !SettingsValid(c) {
			return c, ErrProtocol
		}
	case "geometry":
		if c.Generation == 0 || len(c.Monitors) == 0 || len(c.Monitors) > 16 {
			return c, ErrProtocol
		}
		found := false
		seen := map[uint32]bool{}
		for _, m := range c.Monitors {
			if !m.Valid() || seen[m.ID] {
				return c, ErrProtocol
			}
			seen[m.ID] = true
			if m.ID == c.SelectedMonitor {
				found = true
			}
		}
		if !found {
			return c, ErrProtocol
		}
	case "status":
		if !word("starting streaming paused error closing", c.State) || len(c.Code) > 64 || len(c.Message) > 256 || len(c.Backend) > 32 {
			return c, ErrProtocol
		}
	case "ack":
		if c.Generation == 0 || c.Sequence == 0 {
			return c, ErrProtocol
		}
	case "select-monitor":
		if c.Generation == 0 || c.MonitorID == 0 {
			return c, ErrProtocol
		}
	case "pointer":
		if c.Generation == 0 || c.X < 0 || c.Y < 0 || c.X >= 2560 || c.Y >= 2560 || !word("move down up wheel", c.Action) || c.Button < 0 || c.Button > 4 || c.Delta < -1200 || c.Delta > 1200 {
			return c, ErrProtocol
		}
		if c.Action != "wheel" && c.Delta != 0 {
			return c, ErrProtocol
		}
		if (c.Action == "move" || c.Action == "wheel") && c.Button != 0 {
			return c, ErrProtocol
		}
	case "key":
		if c.Generation == 0 || !SupportedKey(c.Code) {
			return c, ErrProtocol
		}
	case "text":
		if c.Generation == 0 || len(c.Text) > 1024 || c.Text == "" {
			return c, ErrProtocol
		}
	}
	return c, nil
}
func word(list, s string) bool {
	for _, w := range bytes.Fields([]byte(list)) {
		if string(w) == s {
			return true
		}
	}
	return false
}
func Read(r io.Reader, fromViewer bool) ([]byte, error) {
	h := make([]byte, HeaderSize)
	if _, e := io.ReadFull(r, h); e != nil {
		return nil, e
	}
	n, e := length(h, fromViewer)
	if e != nil {
		return nil, e
	}
	p := make([]byte, HeaderSize+n)
	copy(p, h)
	if _, e = io.ReadFull(r, p[HeaderSize:]); e != nil {
		return nil, e
	}
	return p, Validate(p, fromViewer)
}
func length(h []byte, viewer bool) (int, error) {
	if len(h) < HeaderSize || string(h[:4]) != Magic || h[5] != 0 || h[6] != 0 || h[7] != 0 {
		return 0, ErrProtocol
	}
	n := binary.BigEndian.Uint32(h[8:12])
	if h[4] == 1 && n > 0 && n <= MaxControl {
		return int(n), nil
	}
	if !viewer && h[4] == 2 && n > 24 && n <= MaxFrame {
		return int(n), nil
	}
	return 0, ErrProtocol
}
func Validate(p []byte, viewer bool) error {
	n, e := length(p, viewer)
	if e != nil || len(p) != HeaderSize+n {
		return ErrProtocol
	}
	if p[4] == 1 {
		_, e = ParseControl(p[HeaderSize:], viewer)
		return e
	}
	m := p[HeaderSize:]
	if binary.BigEndian.Uint32(m) == 0 || binary.BigEndian.Uint32(m[4:]) == 0 || binary.BigEndian.Uint32(m[8:]) == 0 || binary.BigEndian.Uint32(m[20:]) != 0 {
		return ErrProtocol
	}
	w, h := binary.BigEndian.Uint32(m[12:]), binary.BigEndian.Uint32(m[16:])
	if !Dimensions(w, h, 2560) {
		return ErrProtocol
	}
	cfg, e := jpeg.DecodeConfig(bytes.NewReader(m[24:]))
	if e != nil || cfg.Width != int(w) || cfg.Height != int(h) {
		return ErrProtocol
	}
	return nil
}
func Packet(c Control) []byte { b, _ := json.Marshal(c); return envelope(1, b) }
func envelope(kind byte, b []byte) []byte {
	p := make([]byte, HeaderSize+len(b))
	copy(p, Magic)
	p[4] = kind
	binary.BigEndian.PutUint32(p[8:], uint32(len(b)))
	copy(p[HeaderSize:], b)
	return p
}
func Frame(seq, gen, monitor, w, h uint32, jpg []byte) ([]byte, error) {
	if len(jpg) > MaxFrame-24 {
		return nil, ErrProtocol
	}
	b := make([]byte, 24+len(jpg))
	for i, v := range []uint32{seq, gen, monitor, w, h} {
		binary.BigEndian.PutUint32(b[i*4:], v)
	}
	copy(b[24:], jpg)
	p := envelope(2, b)
	return p, Validate(p, false)
}
func Write(w io.Writer, p []byte) error { _, e := io.Copy(w, bytes.NewReader(p)); return e }

// AwaitStart keeps heartbeats alive while the operator chooses a Windows
// session. Traffic never extends the fixed initialization deadline.
func AwaitStart(conn net.Conn, timeout time.Duration) (Control, error) {
	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)
	lim := rate.NewLimiter(4, 8)
	for {
		p, err := Read(conn, true)
		if err != nil {
			return Control{}, err
		}
		c, err := ParseControl(p[HeaderSize:], true)
		if err != nil || !lim.Allow() {
			return Control{}, ErrProtocol
		}
		switch c.Type {
		case "start":
			return c, nil
		case "ping":
			conn.SetWriteDeadline(deadline)
			if err := Write(conn, Packet(Control{Type: "pong", Nonce: c.Nonce})); err != nil {
				return Control{}, err
			}
		case "release-input":
		case "stop":
			return Control{}, io.EOF
		default:
			return Control{}, ErrProtocol
		}
	}
}
