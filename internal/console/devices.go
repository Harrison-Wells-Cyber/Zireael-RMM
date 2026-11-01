package console

import (
	"net/http"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/agent"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/bootstrap"
)

func (c *Console) devices(w http.ResponseWriter, r *http.Request) {
	devices, err := c.agents.Devices()
	if err != nil {
		fail(w, 500, "Devices unavailable")
		return
	}
	reply(w, 200, devices)
}

func (c *Console) prepareInstaller() error {
	c.publicOnce.Do(func() {
		token, err := c.store.PublicEnrollmentToken()
		if err != nil {
			c.publicErr = err
			return
		}
		invite := agent.Invite{Server: c.origin, CA: c.agents.CA(), Token: token, Mode: "user"}
		c.publicPackage, c.publicErr = c.artifact.PowerShell(invite)
		if c.publicErr == nil {
			c.publicCommand, c.publicErr = bootstrap.Command(invite, c.publicPackage.SHA256)
			if c.publicErr == nil {
				c.publicUninstallCommand, c.publicErr = bootstrap.Command(invite, c.publicPackage.SHA256, "-Uninstall")
			}
			if c.publicErr == nil {
				c.publicReplaceCommand, c.publicErr = bootstrap.Command(invite, c.publicPackage.SHA256, "-Replace")
			}
		}
	})
	return c.publicErr
}

func (c *Console) powerShellPackage(w http.ResponseWriter, r *http.Request) {
	if c.prepareInstaller() != nil {
		fail(w, 500, "Installer unavailable")
		return
	}
	c.publicPackage.Download(w, r)
}

func (c *Console) defaultCommand(w http.ResponseWriter, r *http.Request) {
	if c.prepareInstaller() != nil {
		fail(w, 500, "Installer unavailable")
		return
	}
	reply(w, 200, map[string]any{"command": c.publicCommand, "uninstallCommand": c.publicUninstallCommand, "replaceCommand": c.publicReplaceCommand, "architecture": c.artifact.Architecture})
}

func (c *Console) approve(w http.ResponseWriter, r *http.Request) {
	if !c.fresh(r) {
		fail(w, 401, "Sign in again before approving a device")
		return
	}
	var input struct{}
	if decode(r, &input) != nil {
		fail(w, 400, "Invalid approval request")
		return
	}
	if c.store.ApproveDeviceAs(r.PathValue("id"), c.adminID(r), time.Now()) != nil {
		fail(w, 403, "Device unavailable for approval")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}

func (c *Console) invite(w http.ResponseWriter, r *http.Request) {
	if !c.fresh(r) {
		fail(w, 401, "Sign in again before enrolling a device")
		return
	}
	if c.artifact == nil {
		fail(w, 409, "Configure a built Windows agent using --agent-exe first")
		return
	}
	if c.prepareInstaller() != nil {
		fail(w, 500, "Installer unavailable")
		return
	}
	var input struct {
		Name string `json:"name"`
		Mode string `json:"mode"`
	}
	if decode(r, &input) != nil {
		fail(w, 400, "Invalid enrollment request")
		return
	}
	if input.Mode == "" {
		input.Mode = "user"
	}
	token, expires, err := c.store.CreateInviteAs(input.Name, input.Mode, c.adminID(r), time.Now())
	if err != nil {
		fail(w, 400, "Unable to create enrollment link; check the name and mode")
		return
	}
	invitation := agent.Invite{Server: c.origin, CA: c.agents.CA(), Token: token, Mode: input.Mode}
	command, err := bootstrap.Command(invitation, c.publicPackage.SHA256)
	if err != nil {
		fail(w, 500, "Unable to create installer")
		return
	}
	replacementCommand, err := bootstrap.Command(invitation, c.publicPackage.SHA256, "-Replace")
	if err != nil {
		fail(w, 500, "Unable to create replacement installer")
		return
	}
	localCommand, err := bootstrap.LocalCommand(invitation, c.artifact.SHA256)
	if err != nil {
		fail(w, 500, "Unable to create installer")
		return
	}
	// Fragments are not sent in HTTP request URLs or Referer headers.
	reply(w, 201, map[string]any{"command": command, "replaceCommand": replacementCommand, "localCommand": localCommand, "supportURL": c.origin + "/#invite=" + token, "expires": expires, "architecture": c.artifact.Architecture})
}

// supportInvite accepts only a pre-existing owner-created capability. It cannot
// create invitations, enumerate devices, or authorize any management action.
func (c *Console) supportInvite(w http.ResponseWriter, r *http.Request) {
	if !c.allowClient(r, false) {
		w.Header().Set("Retry-After", "1")
		fail(w, 429, "Please wait a moment, then reload your support link.")
		return
	}
	var input struct {
		Token string `json:"token"`
	}
	if decode(r, &input) != nil {
		fail(w, 400, "Open the complete support link sent to you.")
		return
	}
	mode, expires, err := c.store.PendingInvite(input.Token, time.Now())
	if err != nil {
		fail(w, 404, "This support link has expired, has already been used, or is invalid. Ask your helper for a new link.")
		return
	}
	if c.prepareInstaller() != nil {
		fail(w, 500, "The installer is unavailable. Let your helper know.")
		return
	}
	command, err := bootstrap.Command(agent.Invite{Server: c.origin, CA: c.agents.CA(), Token: input.Token, Mode: mode}, c.publicPackage.SHA256)
	if err != nil {
		fail(w, 500, "The installer is unavailable. Let your helper know.")
		return
	}
	reply(w, 200, map[string]any{"command": command, "mode": mode, "expires": expires, "architecture": c.artifact.Architecture})
}

func (c *Console) revoke(w http.ResponseWriter, r *http.Request) {
	if !c.fresh(r) {
		fail(w, 401, "Sign in again before revoking a device")
		return
	}
	var input struct{}
	if decode(r, &input) != nil {
		fail(w, 400, "Invalid revocation request")
		return
	}
	if c.agents.RevokeAs(r.PathValue("id"), c.adminID(r)) != nil {
		fail(w, 404, "Device unavailable")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}

func (c *Console) disconnect(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if decode(r, &input) != nil {
		fail(w, 400, "Invalid disconnect request")
		return
	}
	if c.agents.DisconnectTemporaryAs(r.PathValue("id"), c.adminID(r)) != nil {
		fail(w, 409, "Only a temporary device session can be ended")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
