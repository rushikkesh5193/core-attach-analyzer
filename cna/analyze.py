"""Per-session attach call-flow validation, KPIs and alarms."""
import json
from collections import Counter, defaultdict
from .flow import ATTACH_FLOW, REJECT, AUTH_FAILURE, ANSWERS_OK, CODE_NAMES, LATENCY_PAIRS

DEFAULT_THRESHOLDS = {"attach_success_min": 97.0, "hss_p95_max_ms": 300.0, "create_session_fail_max": 2.0}


def load_trace(path):
    events = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                ev["ts"] = float(ev["ts"]); ev["session"]; ev["iface"]; ev["msg"]
            except (ValueError, KeyError) as e:
                raise ValueError(f"line {n}: bad event ({e})")
            events.append(ev)
    return events


def analyze_session(events):
    """Returns dict(outcome, detail, failed_answer). Outcomes: SUCCESS, REJECTED, INCOMPLETE, OUT_OF_ORDER."""
    events = sorted(events, key=lambda e: e["ts"])
    idx = 0
    failed_answer = None
    auth_failed = False
    for ev in events:
        key = (ev["iface"], ev["msg"])
        if key == REJECT:
            root = failed_answer or ("authentication failure" if auth_failed else "no failing answer seen")
            return {"outcome": "REJECTED", "detail": f"EMM cause {ev.get('result')}", "root_cause": root,
                    "last_step": ATTACH_FLOW[max(idx - 1, 0)][1]}
        if key == AUTH_FAILURE:
            auth_failed = True
            continue
        if idx < len(ATTACH_FLOW) and key == ATTACH_FLOW[idx]:
            ok = ANSWERS_OK.get(key)
            if ok is not None and str(ev.get("result")) != ok:
                code = str(ev.get("result"))
                failed_answer = f"{ev['msg']} result {code} ({CODE_NAMES.get(code, 'unknown code')})"
            idx += 1
        elif key in ATTACH_FLOW[idx + 1:]:
            return {"outcome": "OUT_OF_ORDER",
                    "detail": f"expected '{ATTACH_FLOW[idx][1]}' but saw '{ev['msg']}'", "root_cause": None,
                    "last_step": ATTACH_FLOW[max(idx - 1, 0)][1]}
    if idx == len(ATTACH_FLOW):
        return {"outcome": "SUCCESS", "detail": "", "root_cause": None, "last_step": ATTACH_FLOW[-1][1]}
    return {"outcome": "INCOMPLETE", "detail": f"no '{ATTACH_FLOW[idx][1]}'", "root_cause": None,
            "last_step": ATTACH_FLOW[max(idx - 1, 0)][1]}


def percentile(values, p):
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, -(-p * len(s) // 100) - 1))  # nearest rank
    return s[int(k)]


def analyze(events, thresholds=None):
    th = dict(DEFAULT_THRESHOLDS, **(thresholds or {}))
    by_session = defaultdict(list)
    for ev in events:
        by_session[ev["session"]].append(ev)
    sessions = {sid: analyze_session(evs) for sid, evs in by_session.items()}

    outcomes = Counter(s["outcome"] for s in sessions.values())
    reject_causes = Counter(s["detail"] for s in sessions.values() if s["outcome"] == "REJECTED")
    root_causes = Counter(s["root_cause"] for s in sessions.values() if s["outcome"] == "REJECTED")
    stalled_at = Counter(s["detail"] for s in sessions.values() if s["outcome"] == "INCOMPLETE")

    lat = {}
    for name, (req, ans) in LATENCY_PAIRS.items():
        vals = []
        for evs in by_session.values():
            t_req = next((e["ts"] for e in evs if (e["iface"], e["msg"]) == req), None)
            t_ans = next((e["ts"] for e in evs if (e["iface"], e["msg"]) == ans), None)
            if t_req is not None and t_ans is not None and t_ans >= t_req:
                vals.append((t_ans - t_req) * 1000.0)
        lat[name] = {"count": len(vals), "p50_ms": percentile(vals, 50), "p95_ms": percentile(vals, 95),
                     "max_ms": max(vals) if vals else None}

    attempts = len(sessions)
    rate = 100.0 * outcomes["SUCCESS"] / attempts if attempts else 0.0
    csr = [e for e in events if (e["iface"], e["msg"]) == ("S11", "Create Session Response")]
    csr_fail = sum(1 for e in csr if str(e.get("result")) != "16")
    csr_rate = 100.0 * csr_fail / len(csr) if csr else 0.0

    alarms = []
    if attempts and rate < th["attach_success_min"]:
        alarms.append(f"ATTACH_SUCCESS_LOW: {rate:.1f}% < {th['attach_success_min']}%")
    for name in ("HSS authentication (AIR->AIA)", "HSS location update (ULR->ULA)"):
        p95 = lat[name]["p95_ms"]
        if p95 is not None and p95 > th["hss_p95_max_ms"]:
            alarms.append(f"HSS_LATENCY_HIGH: {name} p95 {p95:.0f} ms > {th['hss_p95_max_ms']:.0f} ms")
    if csr and csr_rate > th["create_session_fail_max"]:
        alarms.append(f"CREATE_SESSION_FAILURES: {csr_rate:.1f}% > {th['create_session_fail_max']}%")
    if outcomes["INCOMPLETE"]:
        alarms.append(f"STALLED_SESSIONS: {outcomes['INCOMPLETE']} sessions never completed ({dict(stalled_at)})")
    if outcomes["OUT_OF_ORDER"]:
        alarms.append(f"OUT_OF_ORDER_SIGNALLING: {outcomes['OUT_OF_ORDER']} sessions")

    return {"attempts": attempts, "outcomes": dict(outcomes), "attach_success_pct": round(rate, 2),
            "reject_causes": dict(reject_causes), "reject_root_causes": dict(root_causes),
            "stalled_at": dict(stalled_at), "latency": lat,
            "create_session_fail_pct": round(csr_rate, 2), "alarms": alarms, "sessions": sessions}


def render_markdown(r):
    L = ["# Attach analysis", "", f"Attach attempts: **{r['attempts']}**  |  success rate: **{r['attach_success_pct']}%**", "",
         "## Outcomes"]
    L += [f"- {k}: {v}" for k, v in sorted(r["outcomes"].items())]
    L += ["", "## Rejects by EMM cause"] + [f"- {k}: {v}" for k, v in sorted(r["reject_causes"].items())]
    L += ["", "## Reject root causes"] + [f"- {k}: {v}" for k, v in sorted(r["reject_root_causes"].items())]
    L += ["", "## Latency"]
    for k, v in r["latency"].items():
        if v["count"]:
            L.append(f"- {k}: n={v['count']} p50={v['p50_ms']:.0f} ms p95={v['p95_ms']:.0f} ms max={v['max_ms']:.0f} ms")
    L += ["", "## Alarms"] + ([f"- {a}" for a in r["alarms"]] or ["- none"])
    return "\n".join(L) + "\n"
