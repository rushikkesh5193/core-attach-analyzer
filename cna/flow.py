"""Expected LTE initial-attach message sequence (simplified) and result-code tables.

Simplified from the 3GPP attach procedure (TS 23.401 / TS 24.301) as the author understands it from public
material. It is a teaching model, not a conformance test.
"""

ATTACH_FLOW = [
    ("NAS", "Attach Request"),
    ("S6a", "Authentication-Information-Request"),
    ("S6a", "Authentication-Information-Answer"),
    ("NAS", "Authentication Request"),
    ("NAS", "Authentication Response"),
    ("NAS", "Security Mode Command"),
    ("NAS", "Security Mode Complete"),
    ("S6a", "Update-Location-Request"),
    ("S6a", "Update-Location-Answer"),
    ("S11", "Create Session Request"),
    ("S11", "Create Session Response"),
    ("S1AP", "Initial Context Setup Request"),
    ("S1AP", "Initial Context Setup Response"),
    ("NAS", "Attach Accept"),
    ("NAS", "Attach Complete"),
]

REJECT = ("NAS", "Attach Reject")
AUTH_FAILURE = ("NAS", "Authentication Failure")

# Messages whose `result` field is a status code and the value meaning success.
ANSWERS_OK = {
    ("S6a", "Authentication-Information-Answer"): "2001",
    ("S6a", "Update-Location-Answer"): "2001",
    ("S11", "Create Session Response"): "16",
}

CODE_NAMES = {
    "2001": "DIAMETER_SUCCESS",
    "5001": "DIAMETER_ERROR_USER_UNKNOWN",
    "5004": "DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
    "4181": "DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE",
    "16": "GTPv2 Request accepted",
    "73": "GTPv2 No resources available",
    "78": "GTPv2 Missing or unknown APN",
}

# (request, answer) pairs used for latency KPIs.
LATENCY_PAIRS = {
    "HSS authentication (AIR->AIA)": (("S6a", "Authentication-Information-Request"), ("S6a", "Authentication-Information-Answer")),
    "HSS location update (ULR->ULA)": (("S6a", "Update-Location-Request"), ("S6a", "Update-Location-Answer")),
    "SGW session creation (CSReq->CSRsp)": (("S11", "Create Session Request"), ("S11", "Create Session Response")),
}
