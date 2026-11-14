# Live honeypot sensor

The map's ransomware claims and phishing-host inventory remain hourly snapshots.
Live SSH observations are a separate stream from a project-owned Cowrie
honeypot. This integration is **not active until a dedicated sensor server is
provisioned and the Worker migration and secret are deployed**.

## Data flow and privacy

```text
Cowrie JSON log
  -> forwarder reads cowrie.session.connect records only
  -> DB-IP Lite maps source IP to an approximate registered country
  -> one-minute country counts sent over HTTPS
  -> authenticated Worker endpoint upserts into D1 and records a heartbeat
  -> map polls the public, country-only feed once per minute
```

The forwarder never sends or persists source IPs, credentials, session IDs, or
other Cowrie fields. D1 stores only sensor name, minute, ISO country code,
connection count, and ingestion time; rows are retained for 30 days. Cowrie's
own local logs may contain attempted credentials, so protect access to those
logs and set their local retention deliberately. A registered IP country is
not a person's physical location. The map does not infer a remote victim or
draw source-to-destination paths.

## Prerequisites

- A dedicated, isolated Ubuntu VPS with a public address. Do not install the
  honeypot on the web/API host or a server with access to private networks.
- Cowrie installed and configured to write its JSON output to a file readable
  by the forwarder. Follow Cowrie's current official installation and output
  documentation; do not expose Cowrie's management interface.
- Outbound HTTPS from the VPS to `api.threats.top`.
- A high-entropy ingestion token stored as a Cloudflare Worker secret and in a
  root-readable sensor environment file. Do not commit or paste the token into
  chat.

## Deploy the API

From `worker/`, apply the pending D1 migration, add the same random token that
will be installed on the sensor, then deploy the Worker:

```sh
npx wrangler d1 migrations apply threats-platform --remote
npx wrangler secret put SENSOR_INGEST_TOKEN
npx wrangler deploy
```

Generate a token locally with a password manager or a cryptographically secure
random generator. `wrangler secret put` prompts for the value; avoid putting it
in command arguments or shell history. The public endpoint is
`GET https://api.threats.top/api/sensors/events?hours=72`; the collector posts
aggregates to `POST /api/sensors/cowrie/events`.

## Run the forwarder on the sensor

Place a read-only checkout of this repository on the VPS. Create a protected
environment file such as `/etc/threats-sensor.env`:

```ini
SENSOR_INGEST_TOKEN=the-same-secret-entered-in-wrangler
SENSOR_API_URL=https://api.threats.top/api/sensors/cowrie/events
DBIP_CACHE_DIR=/var/lib/threats-sensor/dbip
```

Run the forwarder as an unprivileged account that can read Cowrie's JSON log
and write only to its state directory. Replace the log path with Cowrie's
configured JSON output path:

```sh
python3 /opt/threats-platform/scripts/cowrie_forwarder.py \
  --log-file /path/to/cowrie.json \
  --state /var/lib/threats-sensor/forwarder.json \
  --interval 15
```

Run it under systemd with `EnvironmentFile=/etc/threats-sensor.env` and
`StateDirectory=threats-sensor`. The forwarder reads only connection events,
updates idempotent minute/country counts, and keeps unsent aggregates locally
for retry. When idle, it sends a heartbeat once per minute so the map can
distinguish a quiet sensor from an unconfigured or disconnected one. Its state
file contains no source IPs or credentials. DB-IP Lite is downloaded to the
configured cache and attributed under CC BY 4.0.

## Network and host safety

Use the VPS only as a decoy. Restrict administrative SSH to your own address
and key, expose only the Cowrie listener to the public internet, and prevent
the honeypot from reaching application servers, credentials, control planes,
or private address ranges. Review the VPS provider's acceptable-use rules and
local privacy requirements before exposing it.

After the Worker secret is deployed, the map reports that it is waiting for a
sensor check-in. The forwarder's heartbeat then shows freshness even when no
connection attempts have arrived; observed connection counts remain zero in
that case. Until the Worker secret and sensor heartbeat are active, the map
must not imply that observations exist.
