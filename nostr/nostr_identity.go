package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nbd-wtf/go-nostr"
)

// deriveNostrRoomTag turns the shared room secret into a deterministic Nostr d tag.
// This identifies the room, not the peer.
func deriveNostrRoomTag(secret string) string {
	sum := sha256.Sum256([]byte("nostr-room:" + secret))
	return "room:" + hex.EncodeToString(sum[:])
}

// loadOrCreatePeerNostrKeypair loads a persistent local Nostr identity for this peer.
// The user still only needs to share the room secret. This key is generated locally
// on first run and reused afterwards.
func loadOrCreatePeerNostrKeypair(path string) (privKeyHex string, pubKeyHex string, err error) {
	if path == "" {
		return "", "", fmt.Errorf("empty Nostr key path")
	}

	// Reuse existing key if present.
	if b, err := os.ReadFile(path); err == nil {
		privKeyHex = strings.TrimSpace(string(b))
		pubKeyHex, err = nostr.GetPublicKey(privKeyHex)
		if err != nil {
			return "", "", fmt.Errorf("invalid stored Nostr key in %s: %w", path, err)
		}
		return privKeyHex, pubKeyHex, nil
	}

	// Generate a fresh local peer key.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate Nostr private key: %w", err)
	}
	privKeyHex = hex.EncodeToString(raw)

	pubKeyHex, err = nostr.GetPublicKey(privKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("derive Nostr pubkey: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", "", fmt.Errorf("create key dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(privKeyHex+"\n"), 0o600); err != nil {
		return "", "", fmt.Errorf("store Nostr private key: %w", err)
	}

	return privKeyHex, pubKeyHex, nil
}
