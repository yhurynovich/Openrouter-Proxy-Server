# Changelog

All notable changes to the OpenRouter Proxy Server are documented in this file.

## Fixes

- **Model ID conversion on `/v1/chat/completions`** — The proxy was forwarding the original request body (with normalized model IDs like `gpt-4o`) to OpenRouter instead of the converted OpenRouter ID (like `openai/gpt-4o`), causing HTTP 400 errors. Fixed by sending the model-ID-converted `requestBody` to OpenRouter `server.js:1042-1049`.

- **DNS resolution failures** — When the Docker container's default DNS is broken (common in Docker on Synology NAS), OpenRouter's hostname (`openrouter.ai`) could not be resolved, causing `EAI_AGAIN` errors. Added `OPENROUTER_DNS_SERVERS` environment variable to configure custom DNS servers via `dns.setServers()`, and `DNS_LOOKUP_TIMEOUT_MS` with a custom `lookup` function on both HTTPS and HTTP agents to prevent indefinite DNS hangs `server.js:52-63, 693-736`.

- **Rate limit reset time parsing** — On HTTP 429 responses, the proxy now parses `ratelimit-reset` / `retry-after` / `x-ratelimit-reset` headers and waits until the actual reset time instead of using short exponential backoff. This avoids repeated 429s in rapid succession. The parsing in `KeyManager.parseRateLimitReset()` handles seconds-with-padded-zeros, milliseconds since epoch, Unix timestamps, relative seconds, and HTTP-date formats `services/KeyManager.js:323-377, server.js:1181-1188, 1230-1237`.

- **DNS lookup timeout retries** — `DNS_LOOKUP_TIMEOUT` error code (emitted by the custom DNS lookup timeout) is now included in all network-error retry lists across chat completions streaming, chat completions non-streaming, and messages endpoints `server.js:1152, 1373, 1659`.
