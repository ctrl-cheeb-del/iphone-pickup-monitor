# iphone-pickup-monitor

Get a Telegram message within seconds of an iPhone becoming available for in-store pickup at the Apple Stores you choose.

Built to catch iPhone Duo drops, which typically sell out in 2–5 minutes. It checks every 5 seconds by default, works on any Apple storefront that offers pickup (`uk`, `de`, …), and watches any part numbers you list.

It's a single Go binary. The optional browser helper is only needed for the legacy endpoint (see [Stock endpoints](#stock-endpoints)).

## How it works

Every few seconds it asks Apple's own pickup API whether each part number is available at each target store. It compares the answer with the last result saved in `state.json`. When an item flips from unavailable to available, it sends one Telegram message with the store and a buy link, and alerts again if the item sells out and comes back.

If checks keep failing (three in a row, or a rejected session), it sends a single "availability is unknown" message, then one "recovered" message once checks succeed again. Errors never get turned into a stock result.

### Stock endpoints

**`retail` (recommended)**: `GET /{country}/shop/retail/pickup-message`. It's anonymous: no cookies, no session, no browser. The monitor sends one request for all parts and checks that every configured store and part comes back with a known value.

**`fulfillment` (legacy, the default if `stock_endpoint` is unset)**: `GET /{country}/shop/fulfillment-messages`, the endpoint the product page itself uses. It requires a valid shop session, including Apple's "shield" verification cookie (`shld_bt_ck`). Without one, Apple returns **HTTP 541**. The monitor can renew that session two ways:

- **`renewal_mode: "http"`**: browser-free. Go solves Apple's proof-of-work challenge (`/shop/shld/work/s3/q`, factorisation and SHA digest-search variants) using a client report captured once from a real browser. See [VERIFICATION-PROTOCOL.md](VERIFICATION-PROTOCOL.md).
- **Anything else**: launches Chrome through `renew-session.mjs` (Playwright over CDP) to let the page verify itself, then copies the cookies over.

Renewed cookies are tested against a real stock request before they replace the saved session. Renewal runs 15 minutes before the shield cookie expires.

All Apple requests use a Chrome TLS/HTTP2 fingerprint via [`bogdanfinn/tls-client`](https://github.com/bogdanfinn/tls-client).

## Residential proxies

Polling every few seconds from one IP doesn't last. In testing, a home IP polling the retail endpoint every 15 seconds started getting **HTTP 541** after roughly 30 checks.

The fix is a **rotating residential proxy** in the storefront's country:

- Set `retail_proxy_file` in the config.
- The monitor closes its connection before each check, so the gateway hands out a new residential exit IP every time.
- With a UK gateway, 5-second polling ran for about 21 hours (over 11,000 checks) without a single 541. The only failures were Apple's own store outages (503) and occasional proxy timeouts.

Things to know:

- **Use the storefront's country.** Use a UK exit for `uk` and a German exit for `de`. With [Webshare](https://www.webshare.io/), the country is part of the username, e.g. `USERNAME-gb-rotate` or `USERNAME-de-rotate`.
- **Proxies are for the `retail` endpoint only.** Shield sessions are tied to the IP that earned them. A session created through a proxy got 541 on the fulfillment endpoint even after solving the challenge, so the fulfillment endpoint runs direct, and the monitor refuses a live proxy without `stock_endpoint: "retail"`.
- **Bandwidth adds up.** A retail response for four parts is about 33 KB before compression, plus a new TLS handshake each check. At 5-second polling that can reach roughly 0.5–0.7 GB a day per monitor, so check your plan or poll less often.

Proxy file format (see `proxy.example.json`; `http`, `https` and `socks5` are supported):

```json
{"server": "http://p.webshare.io:80", "username": "USERNAME-gb-rotate", "password": "PASSWORD"}
```

## Setup

Requires Go 1.27+. Node and Chrome are needed only for browser renewal or capturing a verification profile.

```sh
git clone https://github.com/ctrl-cheeb-del/iphone-pickup-monitor && cd iphone-pickup-monitor
go build -o iphone-monitor .
cp config.example.json config.json         # edit it, see below
cp proxy.example.json .proxy.json          # your proxy credentials
echo 'YOUR_BOT_TOKEN' > .telegram-token    # from @BotFather
chmod 600 config.json .proxy.json .telegram-token
./iphone-monitor --test-telegram           # sends a labelled test message
./iphone-monitor --retail-probe --samples 3 --proxy-file .proxy.json   # read-only checks
./iphone-monitor                           # run continuously
```

To get your Telegram chat ID, message your bot, then open `https://api.telegram.org/bot<TOKEN>/getUpdates`.

To keep it running, use the systemd user unit in [`examples/iphone-pickup-monitor.service`](examples/iphone-pickup-monitor.service). It restarts on failure and starts at boot with `loginctl enable-linger`.

To watch several cities or countries, run one copy per area, each with its own `-root` directory containing `config.json` and `.telegram-token`. Give each a `label` so their outage messages can be told apart.

## Configuration

| Key | Meaning |
|---|---|
| `country` | Storefront path segment: `uk` (default), `de`, … |
| `postcode` | Location Apple uses to list nearby stores. All `stores` must appear in that list. |
| `stores` | Store names as Apple returns them, without the "Apple " prefix, e.g. `"Rosenthaler Straße"`. |
| `products` | Map of part number to a display name used in alerts. |
| `interval_seconds` | Seconds between checks (minimum 5). |
| `telegram_chat_id` | Chat to alert. |
| `label` | Optional; tags outage and recovery messages. |
| `stock_endpoint` | `"retail"` (recommended) or unset for the fulfillment endpoint. |
| `retail_proxy_file` | Optional proxy file for the retail endpoint, relative to the root or absolute. |
| `renewal_mode` | `"http"` for browser-free shield renewal; anything else uses the browser. Fulfillment endpoint only. |
| `product_page` | Optional product page URL used to start a shop session. The default is a UK iPhone Duo page; set it for other storefronts. |

### Finding part numbers and store names

Part numbers differ by country: `MK2D4QN/A` in the UK is `MK2D4ZD/A` in Germany. Both are listed in the product page source:

```sh
curl -s https://www.apple.com/de/shop/buy-iphone/iphone-duo \
  | grep -oE '"partNumber":"[A-Z0-9/]+","price":\{"fullPrice":[0-9.]+' | sort -u
```

Store names come back in the retail response. Run `--retail-probe` with a guess: an unknown store fails with "Missing target store or variant", so you know to fix the name.

## Diagnostics

All of these are read-only and send no alerts:

```sh
./iphone-monitor --retail-probe [--samples N --spacing S] [--proxy-file F]
./iphone-monitor --probe                       # fulfillment endpoint with the saved session
./iphone-monitor --probe-http-renewal [--cold] # HTTP shield renewal in a temporary jar
./iphone-monitor --tls-check [--proxy-file F]  # shows the negotiated TLS fingerprint
./iphone-monitor --once                        # one real check, then exit
```

`status.json` shows health, the last success, the next check, the cooldown and the latest stock. Server `Retry-After` cooldowns are respected and survive restarts. HTTP 503 store outages are retried every 60 seconds, and other errors back off exponentially up to an hour.

### Capturing a verification profile (HTTP renewal only)

```sh
npm ci
APPLE_MONITOR_BROWSER=/usr/bin/google-chrome \
  node renew-session.mjs --capture-verification-profile .apple-verification-profile.json
```

This loads the product page in a real Chrome, records the client report it submits, and saves it only if a stock check then succeeds. On a headless Linux machine, run it under `xvfb-run`.

## Limitations

- These are Apple's undocumented internal endpoints, and the shield challenge format can change without notice. Unknown formats fail with a health alert rather than guessing.
- Pickup availability is all it sees. Walk-in stock isn't visible online.
- This isn't affiliated with Apple. Polling at high frequency may break Apple's terms of use; use it responsibly and at your own risk.

## License

MIT
