# Kauri Sync

Kauri Sync is the sync server of [Kauri Clip](https://github.com/VizzleTF/kauri). It keeps snippets, and clipboard history if you turn it on, the same on your Windows and Mac devices. A change on one device reaches the others within a second. You run the server yourself; it needs only PostgreSQL.

- **Encrypted end to end.** Devices encrypt every record and blob with XChaCha20-Poly1305 before upload. The server stores ciphertext it cannot read and cannot tell a snippet from a clip. Record IDs are keyed hashes, sizes are padded into buckets, and there are no plaintext timestamps.
- **No account.** Devices join a *sync chain* with a 24-word sync code. The server knows the chain by `SHA-256(chain_id)` and a public key. It never sees the code.
- **Signed requests.** Each device signs every request with its own Ed25519 key, and each signature works once. A removed device is refused at once.
- **Post-quantum key transport.** Data keys reach devices in hybrid X25519 + ML-KEM-768 envelopes.
- **Pairing.** A device of the chain shows a code such as `ABCD-EFGH-JKMN`, and the new device types it in. The two run SPAKE2 (RFC 9382) through the server, which relays only PAKE messages and ciphertext. The code allows one online guess and no offline guessing.
- **Losing a device.** Removing a device moves the chain to new keys (`/v1/forward`). The lost device can read or write nothing new.

The protocol is specified in [docs/sync.md](https://github.com/VizzleTF/kauri/blob/main/docs/sync.md) in the Kauri Clip repository, with test vectors in `docs/sync-vectors/`. The Go package [`kauri`](kauri) in this repository is the reference client implementation. The vectors come from it, and the end-to-end tests run it against the server.

## Run your own server

With Docker, on a host that a domain name points to, with ports 80 and 443 open:

```sh
git clone https://github.com/VizzleTF/kauri-sync && cd kauri-sync
SYNC_DOMAIN=sync.example.com POSTGRES_PASSWORD=change-me docker compose up -d --build
curl https://sync.example.com/health    # prints "ok"
```

Caddy gets the certificate and forwards to the server, which is not reachable any other way. In Kauri Clip, set the sync server to `https://sync.example.com`.

On a home network or behind Tailscale, where you have no domain:

1. Remove the `caddy` service from `docker-compose.yml`.
2. Publish the server's port as the file describes.

Plain HTTP is fine on loopback or a private network, never over the internet. For a Cloudflare Tunnel, set `TRUSTED_PROXY` to the tunnel's address and `CLIENT_IP_HEADER=CF-Connecting-IP`.

Without Docker, build the binary with Go 1.27 or later and point it at a database:

```sh
go build ./cmd/kauri-sync
DATABASE_URL=postgres://user:password@host:5432/kauri ./kauri-sync
```

The server creates and updates its tables when it starts. More than one instance can share a database, because events travel between instances through Postgres `LISTEN`/`NOTIFY`.

## Configuration

Everything is set with environment variables.

- Sizes take `KiB`, `MiB` or `GiB`, for example `256MiB`.
- Durations take Go units or days, for example `2h` or `30d`.
- For a rate limit, `0` means no limit.

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | required | Postgres URL |
| `PORT` | `8296` | HTTP port |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. Logs are JSON on stderr |
| `ACCESS_LOG` | `true` | Log method, route, status, time and sizes of each request. Bodies, query strings, headers and client addresses are never logged |
| `MAX_BYTES_PER_CHAIN` | `256MiB` | Records and blobs of one chain |
| `MAX_RECORDS` | `100000` | Records of one chain, deleted ones included until they are compacted |
| `MAX_BLOB_BYTES` | `16MiB` | One blob (an image or file of a clip) |
| `MAX_BATCH_RECORDS` | `1000` | Records in one write |
| `MAX_BATCH_BYTES` | `8MiB` | Ciphertext in one write |
| `MAX_EVENT_STREAMS` | `20` | Open event streams per chain on one instance |
| `TOMBSTONE_RETENTION` | `30d` | How long deleted records are kept before compaction |
| `BLOB_GRACE` | `24h` | How long an unused blob is kept |
| `FORWARD_RETENTION` | `90d` | How long a moved chain keeps its forwarding envelopes |
| `CHAINS_PER_IP_PER_HOUR` | `10` | New chains per client address |
| `PAIR_CODES_PER_HOUR` | `20` | Pairing codes per chain |
| `PAIR_JOINS_PER_IP_PER_HOUR` | `30` | Pairing answers per client address |
| `PAIR_READS_PER_IP_PER_HOUR` | `1200` | Pairing slot reads per client address. New devices poll every 2 seconds |
| `TRUSTED_PROXY` | none | Comma-separated addresses or CIDRs of reverse proxies whose client-address header is trusted |
| `CLIENT_IP_HEADER` | `X-Forwarded-For` | The header they set |

`GET /health` answers `ok` while the process runs. `GET /readyz` also checks the database. `kauri-sync healthcheck` calls `/readyz`, for container health checks.

## What the server stores

| Table | Contents |
|---|---|
| `chains` | `SHA-256(chain_id)`, the chain key's public key, the version counter, sizes, the compaction horizon, the current epoch |
| `devices` | Public keys (Ed25519, X25519, ML-KEM), the encrypted device name, added and removed times |
| `keyrings`, `envelopes` | The data key wrapped with a key from the sync code, and sealed to each device |
| `records` | ID (a keyed hash), version, epoch, whether it is deleted, ciphertext |
| `blobs`, `record_blobs` | Ciphertext, and which records use which blob, so that unused blobs can be removed |
| `forwards` | For a moved chain: the new chain secret sealed to each remaining device |
| `pair_slots` | SPAKE2 messages and ciphertext of pairings in progress, for 5 minutes |
| `signatures` | Hashes of used request signatures, for 10 minutes |

From these the server can learn how many records a chain has, their padded sizes, when they change, which records were deleted, and the client address of each request. It cannot learn what they say, what kind they are, or the names of the devices.

## Development

```sh
go test ./...                                  # unit tests
go test -p 1 -tags integration ./...           # end-to-end, with an embedded Postgres
go run ./cmd/kauri-vectors > vectors.json      # regenerate the protocol test vectors
```

## License

MIT, see [LICENSE](LICENSE). Parts come from [arcomium-sync](https://github.com/VizzleTF/arcomium-sync), see [NOTICE](NOTICE).
