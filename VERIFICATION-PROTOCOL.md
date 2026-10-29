# Apple shop verification protocol — observed 28 October 2026 (UK storefront)

This documents the current downloaded verification script and successful tests, not a stable public API. Server-side validation rules are not visible. No cookie signing secret has been recovered or is needed by this implementation: Apple issues the cookies after accepting a challenge response.

## Request flow

1. Load the selected product page using a private candidate cookie jar.
2. When creating an anonymous session from no cookies, request `/uk/shop/beacon/atb` and `/uk/shop/dc`. These provide shop-session cookies including `as_pcts` in observed responses. Omitting this step caused repeated 401 challenge responses in the initial cold-start test.
3. GET `/shop/shld/work/s3/q?jr=<captured score>` to receive a challenge. The script uses an additional `jr_r` error code when the score is 255 (collection failed).
4. Solve the challenge within its deadline and POST the response to the same URL, with credentials/cookies and the body content type `text/plain;charset=UTF-8`, as used by browser fetch with a JSON string body.
5. Collect response cookies in the candidate jar, then request both stock variants through Go tls-client. Promote the candidate only after a complete, valid stock response.

The special `/shop/shld/work/s3/pat` branch in the source applies to supported Safari/iOS clients. The Chrome profile used here follows the challenge branch and reports `patSkip: true`.

## Challenge and response fields

| Field | Observed role |
|---|---|
| `challenge_version` | Selects the solver. Version 1 is factorisation; versions 2 and 3 are digest searches. Unknown versions fail closed. |
| `algorithm` | Digest algorithm, uppercased by the browser. The Go implementation accepts SHA-1, SHA-256, SHA-384 and SHA-512. |
| `salt` | Prefix concatenated with the decimal candidate number before hashing. |
| `challenge` | Target hexadecimal digest. |
| `timeout` | Computation deadline in milliseconds. |
| `low`, `high`, `parts`, `result` | Version 1: bounded, nondecreasing integer factors whose product is `result`. Big integers preserve precision. |
| `X`, `signature`, `t` | Server-issued values observed in the digest challenge. Forwarded unchanged. Their server-side validation and the meaning of `X`/`t` are not established. |
| `number` | Solved integer for digest challenges, or factor list for version 1. |
| `took` | Measured computation time in milliseconds. |
| `flagskv` | Client status flags. Chrome's normal non-PAT path sends `patSkip: true`; error paths in the script contain additional diagnostic flags. |
| `jsa` | Compact client-side assessment/capability report, captured from a working native browser for this installation. |

For digest versions, the script searches integers from 0 through 999,999. Version 3 reverses the final four digest bytes before comparison. The implementation bounds work by both the server timeout and a local limit. The entire HTTP renewal has a 90-second deadline.

The source handles challenge HTTP 401 responses using server-provided `retry_count` and `retry_interval` fields. The implementation respects those within a bounded retry budget and honours HTTP Retry-After instead of immediately retrying.

## Capability report

The source collects user agent, languages, timezone, screen, plugins, canvas, WebGL, audio and fonts. The transmitted `jsa` is a compact assessment, not the entire raw collection:

- `s`: the source's summed/capped suspicion score.
- `f`: abbreviated detected-signal codes.
- `r`: collection error category when applicable.
- `d.u`: browser-family classification.
- `d.p`: whether the media-key API has the expected native shape.
- `d.r`: compact outcomes for seven media-key-system probes.

`.apple-verification-profile.json` stores a real report captured from a native browser on the monitoring host, with its user agent. The monitor reuses that report; it does not run browser collectors on every renewal or claim to recreate a complete browser environment. The Go TLS profile remains Chrome 152 while the captured browser was Chrome 154. Acceptance was tested; an exact browser fingerprint match is not claimed.

## Validation and limits

- HTTP-only renewal with an existing shop session succeeded.
- Two independent starts with no cookies succeeded after adding the bootstrap requests.
- The actual systemd service renewed successfully in HTTP-only mode and retrieved all four stock values. Its cookies and metadata were then removed under a private rollback backup; restarting the service rebuilt an accepted session from scratch at 08:55:05 UTC, without launching a browser.
- The Webshare route could obtain/solve a challenge but the stock endpoint still returned HTTP 541, so fulfillment-endpoint renewal runs direct. The cookie-free retail endpoint does work through rotating residential proxies.
- This does not guarantee acceptance after Apple changes its script, challenge format, session rules or server-side checks. Unknown formats produce a health failure, never an invented stock result. A rejected saved shop session gets at most one fresh bootstrap attempt; server-requested cooldowns suppress that retry.

## Operation

`renewal_mode: "http"` selects browser-free renewal. The systemd unit starts only the Go binary. A private capability profile is required. The old browser renewal remains an explicit fallback implementation, not an automatic dependency of HTTP mode.

For isolated diagnostics:

```sh
./iphone-monitor --probe-http-renewal
./iphone-monitor --probe-http-renewal --cold
```

These tests use temporary candidate jars and do not replace the live cookies. Their safe diagnostic output contains field names/types and status, not challenge secrets or cookie values. Keep `.apple-*` files private.
