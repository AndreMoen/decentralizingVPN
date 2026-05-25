package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// payload carries WireGuard identity info in hole-punch packets.
// WgIP has been removed -- VPN addresses are derived from WgPub + room secret.
type payload struct {
	WgPub string `json:"wg_pub,omitempty"`
	Room  string `json:"room,omitempty"`
}

type packet struct {
	Type    string
	SID     string
	TS      *int64
	Payload *payload
}

func tsNow() int64          { return time.Now().UnixMilli() }
func ptrI64(v int64) *int64 { return &v }

func b64urlEnc(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
func b64urlDec(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func localPayload(wgPub string) *payload {
	if strings.TrimSpace(wgPub) == "" {
		return nil
	}
	return &payload{WgPub: wgPub, Room: room}
}

func mergePayload(old, nw *payload) *payload {
	if old == nil && nw == nil {
		return nil
	}
	out := &payload{}
	if old != nil {
		out.WgPub = old.WgPub
		out.Room = old.Room
	}
	if nw != nil {
		if strings.TrimSpace(nw.WgPub) != "" {
			out.WgPub = nw.WgPub
		}
		if strings.TrimSpace(nw.Room) != "" {
			out.Room = nw.Room
		}
	}
	if strings.TrimSpace(out.WgPub) == "" && strings.TrimSpace(out.Room) == "" {
		return nil
	}
	return out
}

func pack(t, sid string, ts *int64, p *payload) []byte {
	var pay string
	if p != nil {
		if b, err := json.Marshal(p); err == nil && len(b) <= 900 && len(b) > 2 {
			pay = b64urlEnc(b)
		}
	}
	tsPart := ""
	if ts != nil {
		tsPart = strconv.FormatInt(*ts, 10)
	}
	return []byte(Magic + "|" + t + "|" + sid + "|" + tsPart + "|" + pay)
}

func unpack(b []byte) *packet {
	s := string(bytes.TrimSpace(b))
	if !strings.HasPrefix(s, Magic+"|") {
		return nil
	}
	parts := strings.Split(s, "|")
	if len(parts) < 4 {
		return nil
	}
	var tsPtr *int64
	if parts[3] != "" {
		if n, err := strconv.ParseInt(parts[3], 10, 64); err == nil {
			tsPtr = &n
		}
	}
	var pl *payload
	if len(parts) >= 5 && parts[4] != "" {
		if raw, err := b64urlDec(parts[4]); err == nil {
			var tmp payload
			if json.Unmarshal(raw, &tmp) == nil {
				pl = &tmp
			}
		}
	}
	return &packet{Type: parts[1], SID: parts[2], TS: tsPtr, Payload: pl}
}
