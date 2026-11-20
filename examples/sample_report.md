# Attach analysis

Attach attempts: **204**  |  success rate: **90.2%**

## Outcomes
- INCOMPLETE: 6
- OUT_OF_ORDER: 2
- REJECTED: 12
- SUCCESS: 184

## Rejects by EMM cause
- EMM cause 11: 2
- EMM cause 19: 2
- EMM cause 22: 3
- EMM cause 3: 2
- EMM cause 8: 3

## Reject root causes
- Authentication-Information-Answer result 5001 (DIAMETER_ERROR_USER_UNKNOWN): 3
- Create Session Response result 73 (GTPv2 No resources available): 3
- Create Session Response result 78 (GTPv2 Missing or unknown APN): 2
- Update-Location-Answer result 5004 (DIAMETER_ERROR_ROAMING_NOT_ALLOWED): 2
- authentication failure: 2

## Latency
- HSS authentication (AIR->AIA): n=201 p50=55 ms p95=78 ms max=882 ms
- HSS location update (ULR->ULA): n=196 p50=21 ms p95=39 ms max=82 ms
- SGW session creation (CSReq->CSRsp): n=194 p50=24 ms p95=38 ms max=40 ms

## Alarms
- ATTACH_SUCCESS_LOW: 90.2% < 97.0%
- CREATE_SESSION_FAILURES: 2.6% > 2.0%
- STALLED_SESSIONS: 6 sessions never completed ({"no 'Authentication-Information-Answer'": 3, "no 'Initial Context Setup Response'": 3})
- OUT_OF_ORDER_SIGNALLING: 2 sessions
