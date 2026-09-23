# Changelog

All notable changes to the OpenRouter Proxy Server are documented in this file.

## Features

- **Model failover** — When a model fails (overloaded, 5xx, or rate-limited across all API keys), the proxy automatically retries the request with the next model in a configurable failover group. The system tries other API accounts first (full key rotation cycle) before switching models. Configurable via `MODEL_FAILOVER_GROUPS` (JSON array of arrays) and `MAX_MODEL_FAILOVERS` environment variables. When failover occurs, the response includes an `X-Failover-Model: true` header and a log entry. Applies to `/v1/chat/completions` and `/v1/messages` endpoints `server.js:1004-107, 1600-1616, services/FailoverManager.js`.

## Fixes

- **Model ID conversion on `/v1/chat/completions`** — The proxy was forwarding the original request body (with normalized model IDs like `gpt-4o`) to OpenRouter instead of the converted OpenRouter ID (like `openai/gpt-4o`), causing HTTP 400 errors. Fixed by sending the model-ID-converted `requestBody` to OpenRouter `server.js:1042-1049`.

- **DNS resolution failures** — When the Docker container's default DNS is broken (common in Docker on Synology NAS), OpenRouter's hostname (`openrouter.ai`) could not be resolved, causing `EAI_AGAIN` errors. Added `OPENROUTER_DNS_SERVERS` environment variable to configure custom DNS servers via `dns.setServers()`, and `DNS_LOOKUP_TIMEOUT_MS` with a custom `lookup` function on both HTTPS and HTTP agents to prevent indefinite DNS hangs `server.js:52-63, 693-736`.

- **Rate limit reset time parsing** — On HTTP 429 responses, the proxy now parses `ratelimit-reset` / `retry-after` / `x-ratelimit-reset` headers and waits until the actual reset time instead of using short exponential backoff. This avoids repeated 429s in rapid succession. The parsing in `KeyManager.parseRateLimitReset()` handles seconds-with-padded-zeros, milliseconds since epoch, Unix timestamps, relative seconds, and HTTP-date formats `services/KeyManager.js:323-377, server.js:1181-1188, 1230-1237`.

- **DNS lookup timeout retries** — `DNS_LOOKUP_TIMEOUT` error code (emitted by the custom DNS lookup timeout) is now included in all network-error retry lists across chat completions streaming, chat completions non-streaming, and messages endpoints `server.js:1152, 1373, 1659`.

- **Total request timeout exceeded (504)** — Retry wait times (rate limit reset and `NO_AVAILABLE_KEYS` key reset) were capped at the full `TOTAL_REQUEST_TIMEOUT_MS` (90s) rather than the *remaining* budget, allowing total elapsed time to exceed 90s and trigger `Total request timeout exceeded` errors. Fixed by capping all wait times at `TOTAL_REQUEST_TIMEOUT_MS - elapsedMs` and adding a pre-retry elapsed-time check that returns 504 if the budget is exhausted `server.js:1014-1028, 1227-1238, 1235-1248, 1426-1439, 1716-1729`.

- **Streaming errors no longer silently retried/failed-over** — On the streaming path, the proxy retried and failed over while zero bytes had been written to the client, holding the SSE connection open until the client's stale-stream watchdog fired and reported a generic stall. Streaming errors now fail fast: the real upstream status/message is forwarded immediately and the stream is closed, so the agent can react without waiting `server.js:1529-1543`.

- **Real upstream error text in SSE error events** — `normalizeStreamError` now passes `{ exposeDetails: true }` to `normalizeErrorResponse`, bypassing the 5xx `'Upstream service error'` mask. SSE error events carry the actual upstream message (with `sk-…` secrets still redacted), instead of an opaque generic string `server.js:571-648, 686-689`.

- **Tool count limit for agent frameworks** — Added `MAX_TOOL_CALLS` (default 100, max 10000) to allow agentic frameworks (Hermes, OpenHands, Aider) that register 100+ tools to pass request validation `server.js:246, 942-943`.

- **Global error handler no longer masks 4xx as 500** — Every uncaught error was returned as HTTP 500 `"Internal server error"`, including body-parser failures such as malformed JSON (`entity.parse.failed`, HTTP 400) and oversized request bodies (`entity.too.large`, HTTP 413 — the likely cause of the Hermes stall, since 100+ tool schemas can exceed `BODY_LIMIT`). The handler now honors `err.status`/`err.statusCode`, returning the real 4xx status and message, and only masks genuine 5xx `server.js:2116-2141`.

- **Timeout/retry config values were silently ignored above old clamps** — `parseIntEnv()` falls back to the default when a value exceeds its `max`, so the raised `.env`/`compose.yaml` timeouts (e.g. `AXIOS_TIMEOUT=300000`, `TOTAL_REQUEST_TIMEOUT_MS=600000`) were discarded and reverted to 60s/90s. Raised the clamps in `CONFIG` (`AXIOS_TIMEOUT`, `AXIOS_KEEPALIVE_TIMEOUT`, `AXIOS_IDLE_TIMEOUT` max → 600000; `TOTAL_REQUEST_TIMEOUT_MS` max → 900000) so the configured budgets take effect `server.js:205-217`.

## Configuration defaults changed

- Raised default upstream/retry budgets for long-running agent tasks: `AXIOS_TIMEOUT`, `AXIOS_KEEPALIVE_TIMEOUT`, and `AXIOS_IDLE_TIMEOUT` to 300000 ms (5 min), `AXIOS_FREE_SOCKET_TIMEOUT` to 60000 ms, `TOTAL_REQUEST_TIMEOUT_MS` to 600000 ms (10 min), `MAX_RETRIES` / `MAX_RATE_LIMIT_RETRIES` to 10, and `RETRY_DELAY_MS` to 2000 ms. See `.env.example` and `compose.yaml`.
