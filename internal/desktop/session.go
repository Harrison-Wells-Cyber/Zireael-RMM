package desktop

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/time/rate"
	"image"
	"image/jpeg"
	"net"
	"time"
)

type Backend interface {
	Monitors() ([]Monitor, error)
	Capture(Monitor, string) (image.Image, string, error)
	Input(Control, Monitor, uint32, uint32) error
	Release()
	Close()
	Elevated() bool
}
type ClipboardBackend interface {
	ReadClipboard() (string, error)
	WriteClipboard(string) error
}

var ErrClipboardTooLarge = errors.New("clipboard text exceeds transfer limit")

type CaptureError struct {
	Code string
	Err  error
}

func (e *CaptureError) Error() string { return e.Code }
func statusError(err error) string {
	var c *CaptureError
	if errors.As(err, &c) {
		return c.Code
	}
	return "capture_unavailable"
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > MaxFrame-24 {
		return 0, errors.New("encoded frame exceeds limit")
	}
	return b.Buffer.Write(p)
}
func encodeFrame(src image.Image, edge, quality int) ([]byte, uint32, uint32, error) {
	bounds := src.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	if w <= 0 || h <= 0 || !Dimensions(uint32(w), uint32(h), 16384) {
		return nil, 0, 0, ErrProtocol
	}
	out := src
	if w > edge || h > edge {
		nw, nh := w, h
		if w >= h {
			nw = edge
			nh = max(1, h*edge/w)
		} else {
			nh = edge
			nw = max(1, w*edge/h)
		}
		im := image.NewRGBA(image.Rect(0, 0, nw, nh))
		for y := 0; y < nh; y++ {
			for x := 0; x < nw; x++ {
				im.Set(x, y, src.At(bounds.Min.X+x*w/nw, bounds.Min.Y+y*h/nh))
			}
		}
		out = im
		w, h = nw, nh
	}
	var b limitedBuffer
	err := jpeg.Encode(&b, out, &jpeg.Options{Quality: quality})
	return b.Bytes(), uint32(w), uint32(h), err
}

// Serve owns capture and input on its calling thread. Release must be safe
// concurrently, so a stalled capture cannot prevent cancellation releasing keys.
// Its only reader goroutine
// is joined on exit; neither capture nor input has a detached lifetime.
func Serve(ctx context.Context, conn net.Conn, start Control, b Backend) error {
	defer b.Close()
	defer b.Release()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	releaseDone := make(chan struct{})
	stopRelease := context.AfterFunc(ctx, func() { defer close(releaseDone); b.Release() })
	defer func() {
		cancel()
		if !stopRelease() {
			<-releaseDone
		}
	}()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	incoming := make(chan Control, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		lim := rate.NewLimiter(240, 480)
		for {
			p, e := Read(conn, true)
			if e != nil || !lim.Allow() {
				return
			}
			c, e := ParseControl(p[HeaderSize:], true)
			if e != nil {
				return
			}
			select {
			case incoming <- c:
			case <-ctx.Done():
				return
			}
		}
	}()
	defer func() { cancel(); conn.Close(); <-done }()
	write := func(p []byte) error { conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); return Write(conn, p) }
	status := func(state, code, msg, backend string) error {
		return write(Packet(Control{Type: "status", State: state, Code: code, Message: msg, Backend: backend, Elevated: b.Elevated()}))
	}
	monitors, err := b.Monitors()
	if err != nil || len(monitors) == 0 {
		return status("error", "capture_unavailable", "No supported display is available.", "")
	}
	gen := uint32(1)
	selected := monitors[0]
	settings := start
	seq := uint32(0)
	var width, height uint32
	var waiting bool
	var sent time.Time
	var frameReady bool
	geometry := func() error {
		return write(Packet(Control{Type: "geometry", Generation: gen, Monitors: monitors, SelectedMonitor: selected.ID}))
	}
	if err = geometry(); err != nil {
		return err
	}
	if err = status("starting", "", "Starting capture.", ""); err != nil {
		return err
	}
	tick := time.NewTicker(time.Second / time.Duration(settings.MaxFPS))
	defer tick.Stop()
	maintenance := time.NewTicker(time.Second)
	defer maintenance.Stop()
	peer := time.Now()
	lastFrame := time.Now()
	lastPing := time.Now()
	lastError := ""
	pause := func(e error, backend string) error {
		b.Release()
		frameReady = false
		code := statusError(e)
		if lastError == "" {
			// Input can notice a desktop switch while a frame is in flight.
			// Invalidate that frame so its late ACK cannot re-enable input.
			gen++
			waiting = false
			width, height = 0, 0
			if err := geometry(); err != nil {
				return err
			}
		}
		if code != lastError {
			lastError = code
			return status("paused", code, "Desktop is unavailable. Waiting for the interactive desktop.", backend)
		}
		return nil
	}
	nonce := uint32(0)
	bandwidth := rate.NewLimiter(rate.Limit(1<<20), MaxFrame)
	clipboardRate := rate.NewLimiter(2, 2)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case c := <-incoming:
			peer = time.Now()
			switch c.Type {
			case "stop":
				return nil
			case "start":
				return ErrProtocol
			case "ping":
				if err = write(Packet(Control{Type: "pong", Nonce: c.Nonce})); err != nil {
					return err
				}
			case "pong":
				if c.Nonce != nonce {
					return ErrProtocol
				}
			case "ack":
				if c.Generation < gen || c.Sequence < seq {
					continue
				}
				if !waiting || c.Generation != gen || c.Sequence != seq {
					return ErrProtocol
				}
				waiting = false
				frameReady = true
			case "release-input":
				b.Release()
			case "select-monitor":
				if c.Generation != gen {
					continue
				}
				found := false
				for _, m := range monitors {
					if m.ID == c.MonitorID {
						selected = m
						found = true
						break
					}
				}
				if !found {
					return ErrProtocol
				}
				b.Release()
				gen++
				frameReady = false
				waiting = false
				width = 0
				lastFrame = time.Now()
				if err = geometry(); err != nil {
					return err
				}
			case "settings":
				if c.ViewOnly {
					b.Release()
				}
				if c.MaxEdge != settings.MaxEdge || c.Backend != settings.Backend {
					b.Release()
					gen++
					frameReady = false
					waiting = false
					width = 0
					lastFrame = time.Now()
					if err = geometry(); err != nil {
						return err
					}
				}
				settings = c
				tick.Reset(time.Second / time.Duration(settings.MaxFPS))
			case "clipboard-get", "clipboard-set":
				action := "read"
				if c.Type == "clipboard-set" {
					action = "write"
				}
				response := Control{Type: "clipboard", Generation: c.Generation, Nonce: c.Nonce, Action: action}
				clipboard, supported := b.(ClipboardBackend)
				switch {
				case !supported:
					response.Code = "unsupported"
					response.Message = "Update the Windows agent to use clipboard transfer."
				case c.Generation != gen || !frameReady || lastError != "":
					response.Code = "unavailable"
					response.Message = "The desktop is not ready for clipboard transfer."
				case action == "write" && settings.ViewOnly:
					response.Code = "view_only"
					response.Message = "Turn off View only to change the remote clipboard."
				case !clipboardRate.Allow():
					response.Code = "busy"
					response.Message = "Wait a moment before another clipboard request."
				default:
					if action == "read" {
						response.Text, err = clipboard.ReadClipboard()
					} else {
						err = clipboard.WriteClipboard(c.Text)
					}
					if err != nil {
						response.Code = "unavailable"
						response.Message = "Windows clipboard is unavailable. Try again."
						if errors.Is(err, ErrClipboardTooLarge) {
							response.Code = "too_large"
							response.Message = "Clipboard text exceeds the 8 KiB transfer limit."
						}
						response.Text = ""
					}
				}
				packet := Packet(response)
				if len(response.Text) > MaxClipboard || len(packet) > HeaderSize+MaxControl {
					response.Text = ""
					response.Code = "too_large"
					response.Message = "Clipboard text exceeds the 8 KiB transfer limit."
					packet = Packet(response)
				}
				if err = write(packet); err != nil {
					return err
				}
			case "pointer", "key", "text":
				if c.Generation != gen || !frameReady || settings.ViewOnly || lastError != "" {
					continue
				}
				if err = b.Input(c, selected, width, height); err != nil {
					var unavailable *CaptureError
					if errors.As(err, &unavailable) {
						if err = pause(err, ""); err != nil {
							return err
						}
						continue
					}
					b.Release()
					if err = status("streaming", "input_failed", "Windows could not apply the input.", ""); err != nil {
						return err
					}
				}
			default:
				return ErrProtocol
			}
		case <-maintenance.C:
			now := time.Now()
			if now.Sub(peer) > 15*time.Second {
				return errors.New("viewer heartbeat timed out")
			}
			if waiting && now.Sub(sent) > 10*time.Second {
				return status("error", "viewer_stalled", "The viewer stopped acknowledging frames.", "")
			}
			if !frameReady && !waiting && lastError == "" && now.Sub(lastFrame) > 15*time.Second {
				return status("error", "first_frame_timeout", "No frame arrived from the display.", "")
			}
			if now.Sub(lastPing) >= 5*time.Second {
				nonce++
				if err = write(Packet(Control{Type: "ping", Nonce: nonce})); err != nil {
					return err
				}
				lastPing = now
			}
			next, e := b.Monitors()
			if e == nil && !sameMonitors(monitors, next) && len(next) > 0 {
				b.Release()
				monitors = next
				selected = next[0]
				gen++
				frameReady = false
				waiting = false
				width = 0
				lastFrame = now
				if err = geometry(); err != nil {
					return err
				}
			}
		case <-tick.C:
			if waiting {
				continue
			}
			im, backend, e := b.Capture(selected, settings.Backend)
			if e != nil {
				if err = pause(e, backend); err != nil {
					return err
				}
				continue
			}
			if im == nil {
				continue
			}
			jpg, w, h, e := encodeFrame(im, settings.MaxEdge, settings.Quality)
			if e != nil {
				return status("error", "capture_unavailable", "The display frame could not be encoded.", backend)
			}
			if lastError != "" {
				lastError = ""
				gen++
				waiting = false
				if err = geometry(); err != nil {
					return err
				}
			}
			if !bandwidth.AllowN(time.Now(), len(jpg)) {
				continue
			}
			seq++
			width, height = w, h
			p, e := Frame(seq, gen, selected.ID, w, h, jpg)
			if e != nil {
				return e
			}
			if err = write(p); err != nil {
				return err
			}
			waiting = true
			sent = time.Now()
			lastFrame = sent
			if !frameReady {
				if err = status("streaming", "", "Waiting for the first frame acknowledgement.", backend); err != nil {
					return err
				}
			}
		}
	}
}
func sameMonitors(a, b []Monitor) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// FrameIdentity is also useful to relays checking progress without decoding pixels.
func FrameIdentity(p []byte) (seq, gen uint32) {
	return binary.BigEndian.Uint32(p[12:]), binary.BigEndian.Uint32(p[16:])
}
