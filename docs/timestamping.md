# Timestamped audit evidence

Why: a hash chain shows that nobody edited the log *unless they recomputed all the later hashes*. A person with write access to the database can. A signed timestamp from an independent authority fixes the chain's head at a moment in time, which the insider cannot forge. Design: DECISIONS D-031.

## Turn it on (operator)
```
VETO_TSA_URL=https://freetsa.org/tsr          # any RFC 3161 authority (example only; see "Choosing an authority")
VETO_TSA_CA=C:\path\to\authority-chain.pem   # recommended: VETO then verifies every signature before storing
VETO_ANCHOR_INTERVAL_S=3600                   # how often; 0 = no background loop (anchor by hand)
```
Needs the `openssl` command on the server when `VETO_TSA_CA` is set.

## Use it
* `POST /v1/anchors` (admin): timestamp the current head now. "nothing new" if the log did not change.
* `GET /v1/anchors` (any human role): list receipts, the authority, the last error.
* `GET /v1/anchors/verify`: compares the log with every receipt. `ok: false` with "log was rewritten" or "records were removed" is the alarm.
* `GET /v1/anchors/{seq}/receipt`: the receipt for an auditor.

## For an auditor (no trust in the VETO server needed)
1. Download a receipt (`receipt.json`) and the log (`GET /v1/audit?limit=100000` saved as `audit.json`).
2. Get the authority's certificate chain from the authority itself (`authority-chain.pem`).
3. `python scripts/verify_receipt.py receipt.json --ca authority-chain.pem --audit audit.json`
   It checks the digest, the authority's signature (via `openssl ts -verify`), that the exported log is an intact chain, and that the log still holds the anchored record.

## Choosing an authority
A free public authority is fine for a demonstration or a thesis. For evidence that has to stand up legally, use a qualified commercial authority and keep its certificate chain. VETO has been tested against a local OpenSSL authority only (no internet in the build environment), so try your chosen one with `POST /v1/anchors` and `scripts/verify_receipt.py` before relying on it.

## What it does not do
Records written after the latest anchor are not covered yet (shorten the interval for more). A receipt shows the chain existed in that state at that time, not that its contents were true. Timestamping failures never block decisions.
