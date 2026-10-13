# Pulse — API Monitoring Dashboard

A local HTTP GET monitor using Python 3.13, SQLite, and the standard library. Configure explicit HTTP(S) URLs, timeouts, and intervals; see current result, response latency, status, and recent check history. Availability is the ratio of successful 2xx/3xx responses across all recorded checks, not an SLA.

## Run

```powershell
python app.py
```

Open <http://127.0.0.1:8001>. SQLite data is stored in `monitor.db`; set `API_MONITOR_DB` to change its location. Scheduled checks run only while the app is open. Click **Check now** for an immediate request. Stop with Ctrl+C.

## Target safety

Only explicitly entered `http://` and `https://` URLs are accepted. Each target is DNS-resolved and every answer must be a globally routable public address; private, loopback, link-local, reserved, and metadata-service ranges are rejected. The request connects to a validated resolved IP (DNS pinning) while retaining TLS hostname verification, does not follow redirects, and uses a bounded timeout and response read. The app never discovers hosts, scans ranges, or automatically probes infrastructure. Use only services you own or are authorized to monitor; do not add internal/private URLs.

## Tests

```powershell
python -m unittest -v
```

Network behavior is injected/mocked in tests; the test suite does not send external requests. No third-party packages are required.

