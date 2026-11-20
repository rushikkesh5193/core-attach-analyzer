"""Synthetic attach-trace generator with injected faults and an exact ground truth.

Every subscriber uses the test PLMN 001/01 (MCC 001, MNC 01), so nothing refers to a real operator or person.
"""
import random
from .flow import ATTACH_FLOW

SCENARIOS = ["ok", "slow_hss", "user_unknown", "roaming_not_allowed", "hss_timeout", "auth_failure",
             "no_resources", "unknown_apn", "stalled_context", "out_of_order"]


def _answer_result(key):
    return {"S6a": "2001", "S11": "16"}.get(key[0])


def make_session(sid, imsi, scenario, t0, rng):
    flow = [list(x) for x in ATTACH_FLOW]
    ev = []
    t = t0

    def add(iface, msg, result=None, gap=None):
        nonlocal t
        t += gap if gap is not None else rng.uniform(0.005, 0.040)
        ev.append({"ts": round(t, 6), "session": sid, "imsi": imsi, "iface": iface, "msg": msg, "result": result})

    def hss_gap():
        return rng.uniform(0.6, 0.9) if scenario == "slow_hss" else rng.uniform(0.02, 0.08)

    steps = ATTACH_FLOW
    i = 0
    while i < len(steps):
        iface, msg = steps[i]
        res = _answer_result((iface, msg)) if msg.endswith("Answer") or msg == "Create Session Response" else None
        gap = hss_gap() if msg == "Authentication-Information-Answer" else None
        if scenario == "user_unknown" and msg == "Authentication-Information-Answer":
            add(iface, msg, "5001", gap); add("NAS", "Attach Reject", "8"); return ev
        if scenario == "hss_timeout" and msg == "Authentication-Information-Answer":
            return ev
        if scenario == "roaming_not_allowed" and msg == "Update-Location-Answer":
            add(iface, msg, "5004"); add("NAS", "Attach Reject", "11"); return ev
        if scenario == "auth_failure" and msg == "Authentication Response":
            add("NAS", "Authentication Failure", "20"); add("NAS", "Attach Reject", "3"); return ev
        if scenario == "no_resources" and msg == "Create Session Response":
            add(iface, msg, "73"); add("NAS", "Attach Reject", "22"); return ev
        if scenario == "unknown_apn" and msg == "Create Session Response":
            add(iface, msg, "78"); add("NAS", "Attach Reject", "19"); return ev
        if scenario == "stalled_context" and msg == "Initial Context Setup Response":
            return ev
        if scenario == "out_of_order" and msg == "Security Mode Command":
            # Update-Location-Request arrives before Security Mode Command, i.e. before security is established
            add("S6a", "Update-Location-Request"); add(iface, msg); i += 1
            continue
        if scenario == "out_of_order" and (iface, msg) == ("S6a", "Update-Location-Request"):
            i += 1
            continue
        add(iface, msg, res, gap)
        i += 1
    return ev


def generate(seed=7, counts=None):
    """counts: dict scenario -> number of sessions. Returns (events, truth) where truth is exact expected output."""
    rng = random.Random(seed)
    counts = counts or {"ok": 180, "slow_hss": 4, "user_unknown": 3, "roaming_not_allowed": 2, "hss_timeout": 3,
                        "auth_failure": 2, "no_resources": 3, "unknown_apn": 2, "stalled_context": 3, "out_of_order": 2}
    plan = [s for s, n in counts.items() for _ in range(n)]
    rng.shuffle(plan)
    events, t0 = [], 1000.0
    for n, scen in enumerate(plan):
        t0 += rng.uniform(0.1, 1.5)
        events += make_session(f"s{n:04d}", f"00101{n:010d}", scen, t0, rng)
    events.sort(key=lambda e: e["ts"])
    success = counts.get("ok", 0) + counts.get("slow_hss", 0)
    truth = {"attempts": len(plan), "success": success,
             "rejected": sum(counts.get(k, 0) for k in ("user_unknown", "roaming_not_allowed", "auth_failure", "no_resources", "unknown_apn")),
             "incomplete": counts.get("hss_timeout", 0) + counts.get("stalled_context", 0),
             "out_of_order": counts.get("out_of_order", 0),
             "reject_causes": {f"EMM cause {c}": counts.get(s, 0) for s, c in
                               [("user_unknown", "8"), ("roaming_not_allowed", "11"), ("auth_failure", "3"),
                                ("no_resources", "22"), ("unknown_apn", "19")] if counts.get(s, 0)}}
    return events, truth
