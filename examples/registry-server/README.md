# Example Registry Server

A runnable registry for subs handle registration.

The contract subs depends on is just four endpoints and one token — see
[REGISTRY.md](../../REGISTRY.md). Everything else here (how registrations get
in, how they're stored, how they're authorized) is one example of a choice you
make yourself, not part of that contract.

## Architecture

```
┌─────────┐     ┌──────────────────┐     ┌─────────┐
│  Users  │────>│  Registry Server │<────│  subsd  │
└─────────┘     └──────────────────┘     └─────────┘
                  (public)                 (private)
```

- **subsd** pulls pending handles from the registry and stages them
- **subsd** notifies `POST /committed` when handles are committed on-chain

Registrations enter through `POST /register`, which this example guards with
its own key on the assumption they come from a backend once a purchase is
paid. Your registry can take them however it likes — a public form, an admin
panel, a checkout flow. subs never touches that path.

This architecture keeps subsd private (it holds wallet keys) while the registry is the public-facing service.

## Usage

```bash
# Build
cargo build --release -p registry-server

# Run — both keys are required, and must differ
REGISTRY_API_KEY=$(openssl rand -hex 32) \
SUBSD_API_KEY=$(openssl rand -hex 32) \
registry-server --port 8080
```

The server refuses to start if either key is missing or if the two are equal,
so it can never come up unauthenticated by accident.

Then configure subsd to use this registry:
1. Go to Settings in the subsd UI
2. Set Registry Endpoint to `http://localhost:8080`
3. Set Auth Token to your `SUBSD_API_KEY`
4. Click Test — it probes `/health` with the token, so it fails on a bad token, not just an unreachable host

## Endpoints

All authenticated endpoints expect `Authorization: Bearer <key>` and return
`401` otherwise.

### Public

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/status/:handle` | Check registration status (the user's own poll) |

### Requires `REGISTRY_API_KEY` (this example's intake — not part of the subs contract)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/register` | Enqueue a handle for registration |

### Requires `SUBSD_API_KEY` (the subs contract)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Liveness, and confirms the token is accepted |
| GET | `/pending` | Get pending handles to stage |
| POST | `/ack` | Acknowledge handles were staged |
| POST | `/committed` | Notify when handles are committed |

The keys are separate because they have different blast radii: the subsd key
can drain the work queue, the intake key can mint registrations. Only the
subsd key is part of the subs contract — configure it as the Auth Token in
subs' Settings.

## Example Requests

### Enqueue a handle (your backend)

```bash
curl -X POST http://localhost:8080/register \
  -H "Authorization: Bearer $REGISTRY_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "handle": "alice@example",
    "script_pubkey": "5120..."
  }'
```

### Check status (user — no auth)

```bash
curl http://localhost:8080/status/alice@example
```

### Get pending handles (subsd)

```bash
curl -H "Authorization: Bearer $SUBSD_API_KEY" \
  http://localhost:8080/pending
```

### Acknowledge staged (subsd)

```bash
curl -X POST http://localhost:8080/ack \
  -H "Authorization: Bearer $SUBSD_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"handles": ["alice@example"]}'
```

## Production Considerations

This is a minimal example. In production, you should add:

- **User authentication**: OAuth or similar in front of whatever calls `/register`
- **Payment verification**: Check that users have paid before accepting registrations
- **Database**: Use PostgreSQL/MySQL instead of in-memory storage
- **Rate limiting**: Prevent abuse
- **Notifications**: Email/push notifications when handles are committed
- **Monitoring**: Metrics, logging, alerting
