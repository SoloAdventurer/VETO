# Getting started (Windows 11, PowerShell)

You do not need to understand the code to check that it works. There are four levels; do them in order and stop whenever you are satisfied. Commands are for **PowerShell** opened in the repository folder (for example `cd C:\Users\you\VETO`).

## 0. Get the latest code and tools (once)
```powershell
git pull
python --version                      # needs 3.11 or newer; if "not found", install Python from python.org and tick "Add to PATH"
pip install fastapi uvicorn jsonschema pyyaml httpx pytest ruff cryptography "psycopg[binary]"
```
Optional: `openssl --version`. It is bundled with **Git for Windows** at `C:\Program Files\Git\usr\bin`; add that folder to your PATH if the command is not found. Without it only the timestamp tests and the timestamp part of the tour are skipped.

## 1. Run the automated tests (1 minute)
```powershell
python -m pytest backend/tests -q
```
Success looks like `NNN passed, M skipped`. Skipped tests are normal (Postgres tests need a database, some need openssl). **Any "failed" is a real problem; send me the output.** The same checks run on GitHub for every push (the green tick next to a commit).
To run everything GitHub runs: `python scripts/check_invariants.py` and `python -m ruff check backend scripts`.

## 2. Watch the guided tour (20 seconds)
```powershell
python scripts/tour.py
```
It runs the real gateway in memory and narrates ten steps: a tenant is created; an agent does something harmless (allowed); a taped-sign attack is blocked; a clearance change waits for a human; the policy is edited by two people; a Zapier-style hook cannot launder authority; VETO calls a customer's system with a signed webhook; the log is timestamped; and an attacker who rewrites history *and fixes every hash* is caught by the timestamp. Read the indented lines; each says what happened and why.

## 3. Open the dashboard (5 minutes)
Build the screens once (needs Node 22 from nodejs.org):
```powershell
cd frontend; npm ci; npm run build; cd ..
```
Start the server (set your own keys; they must start with `veto_` and be long):
```powershell
$env:PYTHONPATH = "backend"
$env:VETO_BOOTSTRAP_KEY = "veto_choose-a-long-key-here-0001"
$env:VETO_PLATFORM_KEY  = "veto_choose-another-long-key-0002"
$env:VETO_SECRET_KEY    = "any-random-text-at-least-32-characters-long"
python -m uvicorn veto.gateway.app:app --port 8000
```
Open **http://localhost:8000** and sign in with the `VETO_BOOTSTRAP_KEY` value. Click through **Live feed** (run the scripted scenarios: the table is in README.md), **Approvals**, **Containment** (the kill switch) and **Audit trail** (press the integrity check). Stop the server with Ctrl+C. Without `$env:VETO_DB` it keeps everything in memory, so a restart starts clean.
(Docker alternative: `docker compose up --build`, key `veto_demo-only-key-change-me-0000`.)

## 4. Try the newer features by clicking (no coding)
These have no dashboard screen yet, but the server has a built-in form page. With the server running, open **http://localhost:8000/docs**. Click **Authorize** (top right), paste a key, then open any entry, click **Try it out**, edit the box, **Execute**.
* **Create a customer (tenant):** Authorize with the *platform* key. `POST /v1/platform/tenants` with `{"id": "acme", "name": "Acme", "admin_id": "alice"}`. The reply shows alice's key once: copy it, click Authorize again and paste it. You are now Acme's admin.
* **Make an agent and a second admin:** `POST /v1/admin/principals` `{"id": "ops-agent-1", "roles": ["agent"]}` then `POST /v1/admin/principals/ops-agent-1/keys`. Same for `{"id": "bob", "roles": ["admin"]}`. (The policy only knows agents named ops-agent-1, admin-agent-1 and gate-agent-1.)
* **Edit the policy:** `GET /v1/policy` shows the active one. `POST /v1/policy/proposals` with `{"policy": "<the YAML text>"}` shows a diff. Authorize as bob and call `.../proposals/1/activate`. Try activating as alice: it is refused (403).
* **Hook:** `PUT /v1/admin/hooks/lookup` `{"agent_id": "ops-agent-1", "action": "READ_PERSONNEL", "target": {"resource": "personnel", "id": "{employee}"}, "source": "email"}`; then as the agent key `POST /v1/hooks/lookup` `{"employee": "emp-1042"}`.
* **Connector:** needs a public https address that can receive posts. Make a free test address at https://webhook.site, then `PUT /v1/admin/connectors/test` `{"url": "<your webhook.site URL>", "verbs": ["READ_PERSONNEL"]}` (note the signing secret) and `POST /v1/admin/connectors/test/ping`. Then run a READ_PERSONNEL as the agent; the page shows the signed call with the action hash. Use https only; addresses inside your own network are refused on purpose.
* **Timestamps:** set `VETO_TSA_URL` (see docs/timestamping.md), restart, `POST /v1/anchors`, then `GET /v1/anchors/verify`.

## Reading results
* `decision`: allow / allow_monitor / require_approval / block. `status`: executed, executed_unverified (done but VETO cannot inspect the other system), pending_approval, blocked, failed.
* A **403/401** is usually the wrong key for that action (agent keys cannot manage, admins cannot act as agents).
* Everything is in `GET /v1/audit`; every administrative change is in there too.
