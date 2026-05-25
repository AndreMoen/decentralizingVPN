# decentralizingVPN

This repository contains three WireGuard-based peer-discovery variants plus a set of benchmark and analysis scripts:

- `dht/`: peer discovery through the BitTorrent DHT
- `nostr/`: peer discovery through Nostr relays
- `tor/`: peer discovery and failover coordination through a shared Tor onion service
- `testing/`: measurement, benchmarking, and CSV post-processing helpers

All three main programs create a local WireGuard interface, derive a deterministic IPv6 address from the shared room secret plus each peer's WireGuard public key, and then try to establish direct UDP connectivity between peers.

## How The Main Programs Work

The three Go programs share the same core model:

1. Load configuration from `.env.punchwg` in the current working directory, then fall back to process environment variables.
2. Read `WG_PRIVKEY` and `WG_PUBKEY` from the environment, or try `/etc/wireguard/<iface>.conf` if they are not set.
3. Derive the local VPN IPv6 address and the room IPv6 prefix from the shared `ROOM` secret.
4. Open one UDP socket on `WG_PORT` and use it for WireGuard traffic plus discovery/bootstrapping traffic.
5. Create a TUN device named `WG_IFACE`, bring it up, assign the derived IPv6 address, and install a route for the room prefix.
6. Discover peers through the program-specific backend.
7. NAT-punch or connect to peers, then configure WireGuard peers dynamically.

The difference between the programs is only the discovery backend:

- `dht/` announces and discovers peers through the BitTorrent DHT.
- `nostr/` discovers its external address with STUN, publishes it to Nostr relays, and subscribes for other peers' publications.
- `tor/` discovers its external address with STUN, registers it through a shared onion-service registry, and can fail over to host the registry itself if the current host disappears.

## Common Prerequisites

You will generally need:

- Linux with permission to create TUN devices and configure routes
- `go` installed
- `ip` from `iproute2`
- WireGuard userspace support used by `golang.zx2c4.com/wireguard`
- A WireGuard keypair
- Outbound network access

For the `tor/` variant you also need:

- `tor` installed and running
- a Tor SOCKS listener, default `127.0.0.1:9050`
- Tor control enabled

The repo includes a short note in [tor/preReqs.txt](/home/andre/decentralizingVPN/tor/preReqs.txt:1). In practice that means:

- make sure `ROOM` is set
- enable Tor control port access
- install Tor, for example `sudo apt install tor`
- ensure Tor is running

## Shared Configuration

The Go programs do not use command-line flags. They are configured through environment variables, usually via a repo-local `.env.punchwg` file.

Example `.env.punchwg`:

```dotenv
ROOM=my-shared-room-secret
WG_IFACE=wg0
WG_PORT=51820
WG_PRIVKEY=<base64-wireguard-private-key>
WG_PUBKEY=<base64-wireguard-public-key>
```

Common parameters:

- `ROOM`
  - Shared secret that identifies a VPN room.
  - Peers must use the same value to find each other and derive the same room prefix.
  - Default: `secret-meeting-room-123`
- `WG_IFACE`
  - Name of the TUN/WireGuard interface to create.
  - Default: `wg0`
- `WG_PORT`
  - UDP port used for WireGuard and discovery traffic.
  - Default: `51820`
- `WG_PRIVKEY`
  - Base64 WireGuard private key.
  - If unset, the program tries `/etc/wireguard/<WG_IFACE>.conf`.
- `WG_PUBKEY`
  - Base64 WireGuard public key.
  - If unset, the program tries to derive it from the private key loaded from the environment or WireGuard config.

Important notes:

- `.env.punchwg` is loaded from the program's current working directory.
- Values already present in the shell environment take precedence over `.env.punchwg`.
- The programs need privileges to create the interface and install routes, so `sudo` is usually required.

## Running `dht/`

`dht/` uses the BitTorrent DHT as a rendezvous layer. Each peer announces the shared room hash and listens for other peers announcing the same room. When it finds one, it sends repeated UDP `HELLO` probes to punch through NAT and then configures WireGuard for the peer.

Run from the repo root:

```bash
cd dht
sudo go run .
```

Build a binary:

```bash
cd dht
go build -o dhtpunch .
sudo ./dhtpunch
```

Parameters used by `dht/`:

- `ROOM`
  - Shared room secret for DHT lookup.
- `WG_IFACE`
  - Interface to create, for example `wg0`.
- `WG_PORT`
  - UDP listen port.
- `WG_PRIVKEY`
  - Local WireGuard private key.
- `WG_PUBKEY`
  - Local WireGuard public key.

Example:

```bash
cd dht
sudo env ROOM=lab-room WG_IFACE=wg-dht WG_PORT=51820 go run .
```

## Running `nostr/`

`nostr/` uses STUN to learn its public UDP endpoint, publishes that endpoint plus its WireGuard public key to several Nostr relays, subscribes to the same room on those relays, and hole-punches to any peer it discovers.

Run from the repo root:

```bash
cd nostr
sudo go run .
```

Build a binary:

```bash
cd nostr
go build -o nostrpunch .
sudo ./nostrpunch
```

Parameters used by `nostr/`:

- `ROOM`
  - Shared room secret.
- `WG_IFACE`
  - Interface to create.
- `WG_PORT`
  - UDP port used for WireGuard and STUN.
- `WG_PRIVKEY`
  - Local WireGuard private key.
- `WG_PUBKEY`
  - Local WireGuard public key.
- `STUN_SERVERS`
  - Optional comma-separated STUN server list.
  - Example: `stun.l.google.com:19302,stun.cloudflare.com:3478`
- `NOSTR_RELAYS`
  - Optional comma-separated relay URLs.
  - Example: `wss://relay.damus.io,wss://nos.lol`
- `NOSTR_KEY_FILE`
  - Path to the local Nostr identity file.
  - If the file does not exist, the program creates one.
  - Default: `<cwd>/.nostr-peer.key`

Example:

```bash
cd nostr
sudo env \
  ROOM=lab-room \
  WG_IFACE=wg-nostr \
  WG_PORT=51820 \
  STUN_SERVERS=stun.l.google.com:19302,stun.cloudflare.com:3478 \
  NOSTR_RELAYS=wss://relay.damus.io,wss://nos.lol \
  go run .
```

## Running `tor/`

`tor/` uses a deterministic onion address derived from the shared room secret. Peers register their current external UDP endpoint through that onion-hosted registry, fetch the other peers, and then punch directly over UDP for the actual WireGuard path. If the onion registry becomes unreachable, peers can fail over and one of them can take over hosting it.

Run from the repo root:

```bash
cd tor
sudo go run .
```

Build a binary:

```bash
cd tor
go build -o torpunch .
sudo ./torpunch
```

Parameters used by `tor/`:

- `ROOM`
  - Shared room secret. Also determines the deterministic group onion address.
- `WG_IFACE`
  - Interface to create.
- `WG_PORT`
  - UDP port used for WireGuard and STUN.
- `WG_PRIVKEY`
  - Local WireGuard private key.
- `WG_PUBKEY`
  - Local WireGuard public key.
- `TOR_SOCKS`
  - Tor SOCKS proxy address used for outbound onion access.
  - Default: `127.0.0.1:9050`
- `STUN_SERVERS`
  - Optional comma-separated STUN server list.
- `TOR_SERVER_DATA_ROOT`
  - Optional root directory for the dedicated Tor instance that serves the static onion.
  - Default: a temporary directory under `/tmp`
- `TOR_SERVER_CONTROL`
  - Control address for the dedicated onion-serving Tor instance.
  - Default: `127.0.0.1:9053`
- `TOR_SERVER_TARGET`
  - Local HTTP target that the onion service forwards to.
  - Default: `127.0.0.1:18080`
- `TOR_SERVER_BINARY`
  - Tor executable name or path for the dedicated onion-serving instance.
  - Default: `tor`

Example:

```bash
cd tor
sudo env \
  ROOM=lab-room \
  WG_IFACE=wg-tor \
  WG_PORT=51820 \
  TOR_SOCKS=127.0.0.1:9050 \
  TOR_SERVER_CONTROL=127.0.0.1:9053 \
  go run .
```

## Testing And Benchmark Scripts

The scripts in `testing/` are not generic CLIs for end users. Most of them contain hard-coded peer names, IPs, and public keys. Review and update those constants before using them in a different environment.

Most benchmark scripts also:

- restart or kill existing interfaces/processes
- assume root privileges
- write CSV files to `/home/results/...`

### `testing/connectionTimeDHT.py`

Measures how long it takes the DHT variant to establish bidirectional WireGuard traffic to known peers.

Example:

```bash
sudo python3 testing/connectionTimeDHT.py \
  --runs 3 \
  --nr 7 \
  --src /home/andre/decentralizingVPN/dht \
  --binary /tmp/dhtpunch \
  --iface wg0 \
  --out /home/results/handshake_resultsDHT.csv
```

Parameters:

- `--runs`: number of benchmark runs
- `--nr`: number inserted into the generated room name
- `--src`: Go source directory passed to `go build`
- `--binary`: output binary path to build and execute
- `--out`: CSV output path
- `--iface`: WireGuard interface to delete/recreate between runs
- `--no-build`: skip `go build`
- `--interval-seconds`: synchronized start interval between runs

### `testing/connectionTimeNostr.py`

Measures how long it takes the Nostr variant to observe a WireGuard handshake to known peers.

Example:

```bash
sudo python3 testing/connectionTimeNostr.py \
  --runs 3 \
  --nr 7 \
  --src /home/andre/decentralizingVPN/nostr \
  --binary /tmp/nostrpunch \
  --iface wg0 \
  --max-wait 240 \
  --out /home/results/handshake_resultsNostr.csv
```

Parameters:

- `--runs`: number of benchmark runs
- `--nr`: number inserted into the generated room name
- `--src`: Go source directory passed to `go build`
- `--binary`: output binary path to build and execute
- `--out`: CSV output path
- `--iface`: WireGuard interface to recreate between runs
- `--no-build`: skip `go build`
- `--max-wait`: per-run timeout in seconds
- `--interval-seconds`: synchronized run interval

### `testing/tor_onion_host_accurate.py`

Starts the Tor variant early so one machine can act as the dedicated onion host before peer measurements begin.

Example:

```bash
sudo python3 testing/tor_onion_host_accurate.py \
  --runs 2 \
  --nr 7 \
  --src /home/andre/decentralizingVPN/tor \
  --binary /tmp/torpunch \
  --prep-seconds 90 \
  --iface wg0 \
  --out /home/results/onion_host_resultsTor.csv
```

Parameters:

- `--runs`: number of runs
- `--nr`: number inserted into the generated room name
- `--src`: Go source directory passed to `go build`
- `--binary`: output binary path to build and execute
- `--no-build`: skip `go build`
- `--interval-seconds`: run slot spacing
- `--prep-seconds`: how long before the slot the host should start
- `--iface`: WireGuard interface to clean up
- `--out`: CSV output path

### `testing/tor_peer_timer_accurate.py`

Measures Tor-variant handshake timing for selected peers and can exclude a dedicated onion host from timing results.

Example:

```bash
sudo python3 testing/tor_peer_timer_accurate.py \
  --runs 3 \
  --nr 7 \
  --src /home/andre/decentralizingVPN/tor \
  --binary /tmp/torpunch \
  --iface wg0 \
  --max-wait 240 \
  --onion-host-name server \
  --test-peers desktop,peera,peerb,peerc \
  --out /home/results/handshake_resultsTor.csv
```

Parameters:

- `--runs`: number of runs
- `--nr`: number inserted into the generated room name
- `--src`: Go source directory passed to `go build`
- `--binary`: output binary path to build and execute
- `--out`: CSV output path
- `--iface`: WireGuard interface to recreate between runs
- `--no-build`: skip `go build`
- `--max-wait`: timeout after local readiness
- `--interval-seconds`: synchronized run interval
- `--onion-host-name`: peer name to exclude if one node is dedicated to hosting the onion registry
- `--test-peers`: comma-separated subset of peer names to monitor

### `testing/analyze_tor_pair_times.py`

Post-processes CSV output from `tor_peer_timer_accurate.py` and writes corrected directional and pair summaries.

Example:

```bash
python3 testing/analyze_tor_pair_times.py \
  /home/results/handshake_resultsTor_a.csv \
  /home/results/handshake_resultsTor_b.csv \
  --out-directional /home/results/tor_directional_pair_corrected.csv \
  --out-pairs /home/results/tor_pair_summary.csv
```

Parameters:

- `csvs`: one or more input CSV files from `tor_peer_timer_accurate.py`
- `--out-directional`: detailed per-direction output CSV
- `--out-pairs`: summarized pair-level output CSV

### `testing/connectionTimeTailscale.py`

Measures how long it takes peers to become reachable over Tailscale after running `tailscale down` and `tailscale up`.

Example:

```bash
python3 testing/connectionTimeTailscale.py \
  --runs 3 \
  --timeout 120 \
  --port 34999 \
  --down-wait 10 \
  --out /home/results/tailscale_results.csv
```

Parameters:

- `--runs`: number of runs
- `--out`: CSV output path
- `--timeout`: max wait per run in seconds
- `--port`: local TCP port used by the test listener
- `--down-wait`: wait time between `tailscale down` and `tailscale up`
- `--start-at`: optional Unix timestamp for coordinated startup across machines
- `--up-arg`: extra argument passed to `tailscale up`; can be repeated

### `testing/tailscaleTiming.py`

Runs minute-aligned Tailscale reachability tests and writes results to a fixed CSV path.

Example:

```bash
python3 testing/tailscaleTiming.py --runs 10
```

Parameters:

- `--runs`: number of scheduled cycles

### `testing/latency.sh`

Runs `ping`, prints the raw output, computes summary latency metrics, and appends them to `/home/results/latencyTailscale.csv`.

Example:

```bash
bash testing/latency.sh peera
bash testing/latency.sh peerat
```

Parameters:

- `<peer>`: symbolic peer name
  - dVPN names: `desktop`, `server`, `peera`, `peerb`, `peerc`, `laptop`
  - Tailscale names: `desktopt`, `servert`, `peerat`, `peerbt`, `peerct`, `laptopt`

### `testing/timing.sh`

Runs `iperf3` against a selected peer and appends sender/receiver throughput to `/home/results/timing.csv`.

Example:

```bash
bash testing/timing.sh peera
bash testing/timing.sh peerat
```

Parameters:

- `<peer_name_or_ip>`: symbolic peer selector
  - dVPN names: `desktop`, `server`, `peera`, `peerb`, `peerc`, `laptop`
  - Tailscale names: `desktopt`, `servert`, `peerat`, `peerbt`, `peerct`, `laptopt`

## Suggested First Run

If you want the simplest path to try one of the VPN variants manually:

1. Create `.env.punchwg` inside the variant directory you want to run.
2. Put the same `ROOM` value on every peer.
3. Put each peer's own WireGuard private/public key in that file, or make sure `/etc/wireguard/<iface>.conf` exists.
4. Start the same program variant on every peer.

Example for the Nostr variant:

```bash
cd nostr
cat > .env.punchwg <<'EOF'
ROOM=my-shared-room
WG_IFACE=wg0
WG_PORT=51820
WG_PRIVKEY=<this-machine-private-key>
WG_PUBKEY=<this-machine-public-key>
EOF

sudo go run .
```

## Notes And Limitations

- The repo currently documents runtime behavior through code rather than through built-in `--help` commands for the Go binaries.
- The benchmark scripts are environment-specific because peer identities are hard-coded in the source.
- The programs expect Linux networking tools and elevated privileges.
