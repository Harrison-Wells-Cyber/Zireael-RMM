package console

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/management"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/version"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/wire"
)

type agentUpdate struct {
	ID      string    `json:"id"`
	State   string    `json:"state"`
	Version string    `json:"version"`
	SHA256  string    `json:"sha256"`
	Started time.Time `json:"started"`
	Queued  time.Time `json:"queued,omitempty"`
	Message string    `json:"message"`
}
type consoleDevice struct {
	management.DeviceView
	UpdateAvailable bool         `json:"updateAvailable"`
	UpdateReason    string       `json:"updateReason,omitempty"`
	Update          *agentUpdate `json:"update,omitempty"`
}

func (c *Console) updateAvailability(d management.DeviceView) (bool, string) {
	switch {
	case d.Revoked != nil || d.Pending:
		return false, "Device is not approved"
	case c.artifact == nil || !version.Valid(c.artifact.Version):
		return false, "No versioned agent package is configured"
	case d.Architecture != "" && d.Architecture != c.artifact.Architecture:
		return false, "Agent architecture does not match the configured package"
	case d.AgentSHA256 == c.artifact.SHA256:
		return false, "Up to date"
	case version.Valid(d.AgentVersion) && version.Compare(d.AgentVersion, c.artifact.Version) > 0:
		return false, "Agent is newer than the server package"
	case !d.Online:
		return false, "Connect the agent to update"
	default:
		return true, "Update available"
	}
}

// Must be called with c.mu held. Completion requires the authenticated agent to
// report the exact served binary hash; scheduling alone never means success.
func (c *Console) updateViewLocked(d management.DeviceView) *agentUpdate {
	u := c.updates[d.ID]
	if u == nil {
		return nil
	}
	if u.State == "queued" || u.State == "checking" || u.State == "unconfirmed" {
		if d.Online && d.AgentSHA256 == u.SHA256 {
			u.State = "complete"
			u.Message = "Agent updated to " + u.Version
		} else if time.Since(u.Queued) > 5*time.Minute {
			u.State = "unconfirmed"
			u.Message = "The target build has not reconnected. Check the agent or retry the update."
		}
	}
	copy := *u
	return &copy
}
func (c *Console) updateAgent(w http.ResponseWriter, r *http.Request) {
	if !c.fresh(r) {
		fail(w, 401, "Sign in again before updating an agent")
		return
	}
	var input struct{}
	if decode(r, &input) != nil {
		fail(w, 400, "Invalid update request")
		return
	}
	devices, e := c.agents.Devices()
	if e != nil {
		fail(w, 500, "Devices unavailable")
		return
	}
	var device *management.DeviceView
	for _, d := range devices {
		if d.ID == r.PathValue("id") {
			copy := d
			device = &copy
			break
		}
	}
	if device == nil {
		fail(w, 404, "Device unavailable")
		return
	}
	if ok, reason := c.updateAvailability(*device); !ok {
		fail(w, 409, reason)
		return
	}
	request := make([]byte, 16)
	if _, e = rand.Read(request); e != nil {
		fail(w, 500, "Update unavailable")
		return
	}
	id := hex.EncodeToString(request)
	script, e := c.artifact.UpdateScript(c.origin, device.ID, id)
	if e != nil {
		fail(w, 500, "Update script unavailable")
		return
	}
	operation := wire.Operation{Kind: "command", Script: script, Timeout: 600}
	if operation.Validate() != nil {
		fail(w, 500, "Invalid update package")
		return
	}
	c.mu.Lock()
	previous := c.updateViewLocked(*device)
	if previous != nil && (previous.State == "staging" || previous.State == "queued" || previous.State == "checking") {
		c.mu.Unlock()
		fail(w, 409, "An update is already in progress")
		return
	}
	if c.updates == nil {
		c.updates = map[string]*agentUpdate{}
	}
	update := &agentUpdate{ID: id, State: "staging", Version: c.artifact.Version, SHA256: c.artifact.SHA256, Started: time.Now().UTC(), Message: "Downloading and verifying the agent on the device…"}
	c.updates[device.ID] = update
	c.mu.Unlock()
	finish := func(state, message string) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.updates[device.ID] == update && update.State != "complete" {
			update.State = state
			update.Message = message
			if state == "queued" || state == "checking" {
				update.Queued = time.Now().UTC()
			}
		}
	}
	if c.store.RecordActiveActor("device.update.requested:"+device.ID, c.adminID(r), time.Now()) != nil {
		finish("failed", "Update authorization ended")
		fail(w, 403, "Update authorization ended")
		return
	}
	streamDeadline(w)
	ctx, cancel := c.operationContext(r)
	defer cancel()
	conn, closeOperation, e := c.agents.OperationAs(ctx, device.ID, operation, c.adminID(r))
	if e != nil {
		finish("failed", e.Error())
		fail(w, 409, e.Error())
		return
	}
	defer closeOperation()
	var output bytes.Buffer
	for {
		var result wire.Result
		e = wire.Read(conn, &result)
		if e != nil {
			state, message := "checking", "Connection ended before confirmation. Waiting for the target build to reconnect…"
			if strings.Contains(output.String(), "ZIREAEL_UPDATE_QUEUED:"+id) {
				state, message = "queued", "Update staged. Waiting for the new agent to reconnect…"
			}
			finish(state, message)
			c.mu.Lock()
			response := *update
			c.mu.Unlock()
			reply(w, 202, response)
			return
		}
		if result.Type == "output" {
			if output.Len()+len(result.Data) > 16<<10 || len(result.Data) > wire.ChunkSize {
				e = errors.New("invalid update output")
				break
			}
			output.Write(result.Data)
			continue
		}
		if result.Type != "done" || result.ExitCode != 0 {
			if result.Error != "" {
				output.WriteString(result.Error)
			}
			e = errors.New("updater preparation failed")
			break
		}
		if !strings.Contains(output.String(), "ZIREAEL_UPDATE_QUEUED:"+id) {
			e = errors.New("update handoff was not confirmed")
			break
		}
		finish("queued", "Update staged. Waiting for the new agent to reconnect…")
		_ = c.store.RecordActor("device.update.queued:"+device.ID, c.adminID(r), time.Now())
		c.mu.Lock()
		response := *update
		c.mu.Unlock()
		reply(w, 202, response)
		return
	}
	message := strings.TrimSpace(output.String())
	if message == "" {
		message = "Update preparation failed: " + e.Error()
	}
	if len(message) > 2048 {
		message = message[:2048]
	}
	finish("failed", message)
	_ = c.store.RecordActor("device.update.failed:"+device.ID, c.adminID(r), time.Now())
	fail(w, 502, message)
}
