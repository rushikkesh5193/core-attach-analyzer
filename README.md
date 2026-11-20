# core-attach-analyzer

A small Python tool that reads a signalling trace from a 4G (LTE) core network, checks each subscriber's **initial attach** against the expected call flow, and reports the **KPIs and alarms** a core operations engineer would look at: attach success rate, reject causes, stalled sessions, out-of-order signalling and HSS/SGW response times.

Python standard library only (tested on 3.13).

> **Read this first.** The trace is **synthetic**, produced by `cna/synth.py`. It follows the attach procedure (NAS on S1, S6a Diameter to the HSS, GTPv2-C on S11 to the SGW, S1AP context setup) as I understand it from public 3GPP material (TS 23.401, TS 24.301, TS 29.272, TS 29.274). The flow is simplified, and the cause-code pairings (for example which EMM cause goes with which Diameter result) are illustrative. This project shows how I approach call-flow and KPI analysis. It is **not** evidence of working on a live operator network. All subscribers use the test PLMN 001/01.

## What it does

* **Call-flow validation.** Each session is walked against the 15-step attach flow. Outcomes: `SUCCESS`, `REJECTED` (with the EMM cause and the root cause found earlier in the flow), `INCOMPLETE` (names the missing step) and `OUT_OF_ORDER` (names the expected and the seen message).
* **Root cause.** A reject is traced back to the failing answer, for example `Authentication-Information-Answer result 5001 (DIAMETER_ERROR_USER_UNKNOWN)` or `Create Session Response result 73 (GTPv2 No resources available)`.
* **KPIs.** Attach success rate, reject causes, p50/p95/max latency for AIR->AIA, ULR->ULA and CSReq->CSRsp, create-session failure rate.
* **Alarms** with configurable thresholds: `ATTACH_SUCCESS_LOW`, `HSS_LATENCY_HIGH`, `CREATE_SESSION_FAILURES`, `STALLED_SESSIONS`, `OUT_OF_ORDER_SIGNALLING`.

## Use

```bash
python3 -m cna generate examples/sample_trace.jsonl           # synthetic trace, 204 sessions
python3 -m cna analyze examples/sample_trace.jsonl            # Markdown report
python3 -m cna analyze examples/sample_trace.jsonl --json
python3 -m cna analyze trace.jsonl --attach-min 99 --hss-p95-max-ms 200 --fail-on-alarm   # exit 2 on alarm
python3 -m unittest discover -s tests
```

Trace format, one JSON object per line: `{"ts": 1000.5, "session": "s0001", "imsi": "...", "iface": "S6a", "msg": "Authentication-Information-Answer", "result": "2001"}`.

## Tests

13 tests. The main one generates a trace with a known number of each injected fault (10 scenarios) and checks that the analyzer's counts and reject causes equal the generator's ground truth exactly, on several seeds. Others cover root causes, missing-step reporting, a clean network (no alarms), slow-HSS latency, bad input lines and the CLI exit code. I also broke the analyzer on purpose three times (inverted success check, ignored auth failure, skipped first step); the tests caught each one, and the third exposed a missing test that I then added.

## Limitations

Attach only: no detach, TAU, handover, paging, 3G/2G (SGSN, MSC) or charging (Gy/Gz) flows. Messages are matched by session id, so a real trace would first need correlating by IMSI, S1AP IDs and GTP TEIDs. Latency is from the trace timestamps only. There is no SS7/MAP or SIP.

## Possible extensions

Add the 3G PS attach and PDP context activation flow, a roaming S6a path through a DRA, a Gy/Diameter charging check, and a Wireshark/pcap-JSON importer.
