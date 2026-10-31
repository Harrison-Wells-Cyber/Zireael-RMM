// Package wire bounds application messages carried inside the authenticated tunnel.
package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const MaxMessage = 64 << 10
const Version = 1

type EnrollmentRequest struct {
	Token    string `json:"token"`
	CSR      []byte `json:"csr"`
	Hostname string `json:"hostname,omitempty"`
}
type EnrollmentResponse struct {
	DeviceID    string `json:"deviceID"`
	Certificate []byte `json:"certificate"`
	Mode        string `json:"mode"`
	Pending     bool   `json:"pending,omitempty"`
	// Decode-only compatibility with older servers; never used or sent by new servers.
	PairingCode string `json:"pairingCode,omitempty"`
	Error       string `json:"error,omitempty"`
}
type Hello struct {
	Version      int    `json:"version"`
	Hostname     string `json:"hostname"`
	Username     string `json:"username"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Mode         string `json:"mode"`
	Elevated     bool   `json:"elevated"`
}
type Control struct {
	Type     string `json:"type"`
	DeviceID string `json:"deviceID,omitempty"`
	Ticket   string `json:"ticket,omitempty"`
}

func Write(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > MaxMessage {
		return errors.New("message too large")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if _, err = io.Copy(w, bytes.NewReader(header[:])); err != nil {
		return err
	}
	_, err = io.Copy(w, bytes.NewReader(data))
	return err
}

func Read(r io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxMessage {
		return errors.New("invalid message size")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
