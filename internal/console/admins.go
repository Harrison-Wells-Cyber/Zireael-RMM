package console

import (
	"encoding/base64"
	"net/http"
	"time"
)

func (c *Console) admins(w http.ResponseWriter, r *http.Request) {
	list, err := c.store.Admins()
	if err != nil {
		fail(w, 500, "Admins unavailable")
		return
	}
	reply(w, 200, list)
}

func (c *Console) adminInvite(w http.ResponseWriter, r *http.Request) {
	if !c.fresh(r) {
		fail(w, 401, "Sign in again before inviting an admin")
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if decode(r, &in) != nil {
		fail(w, 400, "Invalid administrator name")
		return
	}
	token, expires, err := c.store.CreateAdminInvite(in.Name, c.adminID(r), time.Now())
	if err != nil {
		fail(w, 400, "Name unavailable or admin limit reached")
		return
	}
	reply(w, 201, map[string]any{"url": c.origin + "/admin#admin-invite=" + token, "expires": expires})
}

func (c *Console) adminRevoke(w http.ResponseWriter, r *http.Request) {
	if !c.fresh(r) {
		fail(w, 401, "Sign in again before revoking an admin")
		return
	}
	var in struct{}
	if decode(r, &in) != nil {
		fail(w, 400, "Invalid revocation request")
		return
	}
	id, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil || len(id) != 32 {
		fail(w, 400, "Invalid admin ID")
		return
	}
	if err = c.store.RevokeAdmin(c.adminID(r), id, time.Now()); err != nil {
		fail(w, 403, "Admin cannot be revoked")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
