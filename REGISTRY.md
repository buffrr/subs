# Building a registry for subs

A **registry** is the service that collects handle requests. `subs` stays
private — it holds wallet keys — and reaches out to the registry to collect
work.

```
┌──────────────────┐            ┌─────────┐
│     Registry     │ ◀───────── │  subs   │
└──────────────────┘   polls    └─────────┘
     (yours)                    (private)
```

**subs always initiates.** The registry never calls subs, never needs to reach
it, and never needs a public address for it. Your registry is an HTTP server
that subs polls.

## Scope

This document covers **only** the four endpoints subs calls. Everything else
about your registry is yours to decide and subs neither sees nor cares about:

- how handle requests get in — a public form, a paid checkout, an admin panel
- how you authenticate, bill, or rate-limit the people making requests
- how you store registrations, notify users, or expose status to them

Implement the four endpoints below and subs will work with it.
[`examples/registry-server`](examples/registry-server) is a working
implementation you can run and read; the intake it happens to ship is
illustrative, not part of this contract.

---

## The cycle

Each pass, subs:

1. `GET /pending` — collect handles awaiting registration
2. stages them locally (validating and de-duplicating)
3. `POST /ack` — report which ones it took
4. publishes certificates to the relay network

Steps 1–3 are what your registry participates in. Step 4 is internal to subs.

Later, when a batch is committed on-chain, subs can call
[`POST /committed`](#post-committed) — that one is **not** automatic.

---

## Authentication

All four endpoints are authenticated with a single shared bearer token:

```
Authorization: Bearer <token>
```

Configure it in subs under **Settings → Registry Server → Auth Token**. Reject
anything without a valid token with **`401`**. subs surfaces `401` and `403`
distinctly from other failures, so an operator sees "registry rejected the auth
token" rather than a generic upstream error.

This token grants access to your work queue — reading pending handles and
marking them staged or committed. If other systems of yours write to the
registry, give them their own credentials; there's no reason for them to share
the one subs holds.

**`/health` is authenticated too**, deliberately. subs' **Test** button probes
it, so a successful test proves both reachability *and* that the token is
accepted — rather than showing green for a registry that will reject every
request after it. If you need an open liveness probe for a load balancer,
expose it on a path subs doesn't use.

---

## Endpoints

### `GET /health`

Return `200` with any body.

### `GET /pending`

Return handles waiting to be staged.

```json
{
  "handles": [
    { "handle": "alice@example", "script_pubkey": "5120aabb…" },
    { "handle": "bob@example",   "script_pubkey": "5120ccdd…" }
  ]
}
```

| Field | Type | Notes |
|---|---|---|
| `handle` | string | `name@space` format. Must parse — see [Handle validation](#handle-validation). |
| `script_pubkey` | string | Hex-encoded script pubkey of the owner's taproot address. |

Return `{"handles": []}` when there's nothing pending — not `404`.

**Any non-2xx aborts the entire sync**, including the ack step, so nothing is
staged that pass. subs retries on the next cycle. The request times out after
10 seconds.

Returning already-staged handles is harmless — subs de-duplicates — but
filtering them keeps payloads small.

### `POST /ack`

Called after subs stages the handles it pulled.

```json
{ "handles": ["alice@example", "bob@example"] }
```

Move these out of your pending set. Return `2xx`; the body is ignored.

**This must be idempotent.** subs acks every handle it pulled, including ones
already staged locally, and re-acks after a failure. Re-acking an
already-acked handle must succeed, not error.

If the ack fails, subs logs it and continues — staging already succeeded on its
side. Your registry still has those handles pending, so the next cycle
re-pulls, re-stages (a no-op), and re-acks. **The flow self-heals, but only if
`/ack` is idempotent.**

### `POST /committed`

```json
{ "root": "<commitment root hex>", "handles": ["alice@example", "bob@example"] }
```

Mark these committed and record the root. Return `2xx`.

**This is not automatic.** It fires only when someone calls
`POST /registry/notify` on subs with a `space` and `root`; nothing triggers it
on a timer. If you need committed state and aren't calling `/registry/notify`,
track it by watching the chain or by querying the relay network for the
handle's certificate.

---

## Delivery semantics

**At-least-once, never exactly-once.** A handle may be delivered more than once
— an ack that fails after subs staged the handle is the ordinary case. Design
so a repeat delivery is a no-op.

**subs is the source of truth for what is registered**, not your registry.
`/ack` means subs accepted a handle into staging; it does not mean the handle
is committed on-chain. Only the commit notification means that.

---

## Handle validation

`handle` must parse as a spaces name in `name@space` form. Handles that don't
parse are **skipped and never acked** — so they stay pending on your side and
are re-pulled on every cycle, forever.

Validate at intake. A malformed handle accepted into your pending queue becomes
a permanent poison entry.

subs may also decline to stage a well-formed handle:

| Reason | Meaning |
|---|---|
| `already staged` | Same handle and script pubkey already pending locally |
| `already committed` | Already committed on-chain |
| `already staged with different spk` | Conflicts with a pending entry under a different owner |
| `already committed with different spk` | The handle is taken |

These are logged by subs and **still acked** — they're settled outcomes, not
retryable failures. The last two mean the request cannot be fulfilled; your
registry has no way to learn this today, so surfacing it to users requires
polling on-chain state yourself.

---

## Configuring subs

In subs' **Settings → Registry Server**:

1. Set **Endpoint** to your base URL (e.g. `https://registry.example.com`)
2. Set **Auth Token** to the token your registry expects
3. Click **Test** — it probes `/health` with the token, so it fails on a bad
   token, not just an unreachable host
4. Optionally enable **Automatic Sync**

With automatic sync **off**, the cycle runs only on **Sync Now** (or
`POST /registry/sync`).

With it **on**, subs runs continuously: every 30 seconds when idle, every 5
seconds while certificates remain to publish. It defaults to off because
publishing broadcasts to the relay network.

---

## Checklist

- [ ] `/health`, `/pending`, `/ack`, `/committed` all require the bearer token
- [ ] Missing or wrong token returns `401`
- [ ] `GET /pending` returns the documented shape, `{"handles": []}` when empty
- [ ] `POST /ack` is idempotent and returns `2xx` for already-acked handles
- [ ] Handles are validated as `name@space` **at intake**
- [ ] Repeat delivery of the same handle is a no-op
- [ ] `POST /committed` implemented, if you need committed state
