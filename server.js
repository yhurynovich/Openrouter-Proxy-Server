import express from 'express';
import dotenv from 'dotenv';
import axios from 'axios';
import rateLimit from 'express-rate-limit';
import https from 'https';
import http from 'http';
import dns from 'dns';
import { timingSafeEqual, randomUUID } from 'crypto';
import keyManager, { KeyManager } from './services/KeyManager.js';
import failoverManager from './services/FailoverManager.js';
import { requestLoggingMiddleware, logError, logInfo } from './services/logger.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { mkdir } from 'fs/promises';
import net from 'net';
import ipaddr from 'ipaddr.js';
import { createAbortSignal, classifyError, isRateLimitError, calculateRetryDelay, isClientDisconnect, logRetry, checkTotalTimeout } from './services/RetryHelper.js';

dotenv.config();

// Sanitize header values to prevent header injection
function sanitizeHeaderValue(value) {
  if (typeof value !== 'string') return '';
  // Strip newlines, carriage returns, and all C0 control characters + DEL
  return value.replace(/[\x00-\x1F\x7F]/g, '').substring(0, 500);
}

// Forward the calling app's own OpenRouter attribution headers, if it sent any.
// OpenRouter gates some ":free" models to recognised agentic harnesses using these
// headers, so dropping them can turn a working client into a 403. Only what the client
// actually sent is forwarded; nothing is invented.
function forwardedAttributionHeaders(req) {
  const out = {};
  const title = req.headers['x-openrouter-title'];
  const categories = req.headers['x-openrouter-categories'];
  if (typeof title === 'string' && title) out['X-OpenRouter-Title'] = sanitizeHeaderValue(title);
  if (typeof categories === 'string' && categories) out['X-OpenRouter-Categories'] = sanitizeHeaderValue(categories);
  return out;
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost', 'metadata.google.internal', 'metadata',
  'metadata.azure.com',
]);

// Private/reserved IP ranges to block (ipaddr.js range names)
const BLOCKED_RANGES = new Set([
  'private', 'loopback', 'linkLocal', 'uniqueLocal', 'reserved',
  'carrierGradeNat', 'unspecified',
]);

// Normalize non-canonical IPv4 encodings (hex, octal, decimal, abbreviated) to dotted-decimal
function normalizeNonCanonicalIPv4(str) {
  if (/^0x[0-9a-f]+$/i.test(str)) {
    const num = parseInt(str, 16);
    if (num >= 0 && num <= 0xffffffff) {
      return [
        (num >>> 24) & 0xff, (num >>> 16) & 0xff,
        (num >>> 8) & 0xff, num & 0xff,
      ].join('.');
    }
  }
  if (/^\d+$/.test(str)) {
    const num = parseInt(str, 10);
    if (num >= 0 && num <= 0xffffffff) {
      return [
        (num >>> 24) & 0xff, (num >>> 16) & 0xff,
        (num >>> 8) & 0xff, num & 0xff,
      ].join('.');
    }
  }
  if (str.includes('.')) {
    const parts = str.split('.');
    if (parts.length >= 2 && parts.length <= 4) {
      const dec = parts.map(p => {
        if (/^0x[0-9a-f]+$/i.test(p)) return parseInt(p, 16);
        if (/^0[0-7]+$/.test(p)) return parseInt(p, 8);
        return parseInt(p, 10);
      });
      if (dec.every(d => !isNaN(d) && d >= 0 && d <= 255)) {
        while (dec.length < 4) dec.push(0);
        return dec.join('.');
      }
    }
  }
  return null;
}

// Check if an IP address is in a private/reserved range using proper parsing
function isPrivateOrInternal(hostname) {
  if (BLOCKED_HOSTNAMES.has(hostname.toLowerCase())) return true;
  const clean = hostname.replace(/^\[|\]$/g, '').toLowerCase();

  // Handle non-canonical IPv4 encodings (hex, octal, decimal, abbreviated)
  const normalized = normalizeNonCanonicalIPv4(clean);
  if (normalized) {
    try {
      const addr = ipaddr.parse(normalized);
      return BLOCKED_RANGES.has(addr.range());
    } catch {
      return true;
    }
  }

  // Canonical IPv4
  if (net.isIPv4(clean)) {
    try {
      const addr = ipaddr.parse(clean);
      return BLOCKED_RANGES.has(addr.range());
    } catch {
      return true;
    }
  }

  // Canonical IPv6 (including IPv4-mapped IPv6 like ::ffff:7f00:1)
  if (net.isIPv6(clean)) {
    try {
      const addr = ipaddr.parse(clean);
      if (addr.isIPv4MappedAddress()) {
        return BLOCKED_RANGES.has(addr.toIPv4Address().range());
      }
      return BLOCKED_RANGES.has(addr.range());
    } catch {
      return true;
    }
  }

  return false;
}

// Resolve hostname and check if any resulting IP is private/reserved (DNS rebinding protection)
async function hostnameResolvesToPrivate(hostname) {
  return new Promise((resolve) => {
    let pending = 2;
    let isPrivate = false;
    const done = (val) => {
      if (pending <= 0) return;
      isPrivate = isPrivate || val;
      pending--;
      if (pending === 0) resolve(isPrivate);
    };

    dnsResolver.resolve4(hostname, (err, addresses) => {
      if (err || !addresses || addresses.length === 0) { done(false); return; }
      done(addresses.some(addr => isPrivateOrInternal(addr)));
    });

    dnsResolver.resolve6(hostname, (err, addresses) => {
      if (err || !addresses || addresses.length === 0) { done(false); return; }
      done(addresses.some(addr => isPrivateOrInternal(addr)));
    });

    setTimeout(() => resolve(isPrivate), CONFIG.DNS_LOOKUP_TIMEOUT_MS);
  });
}

// Safely stringify objects, falling back to String() on error
function safeStringify(obj) {
  try {
    return JSON.stringify(obj);
  } catch {
    return String(obj);
  }
}

function validateImageUrl(url) {
  if (typeof url !== 'string') return false;
  if (url.length > 2048) return false;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
  const hostname = parsed.hostname;
  if (hostname === 'localhost' || isPrivateOrInternal(hostname)) return false;
  return true;
}

// Full DNS rebinding protection available via async function:
// async function validateImageUrlAsync(url) { ... await hostnameResolvesToPrivate(hostname) ... }

// Configuration constants
// Parse integer from env with validation, clamping to [min, max]
function parseIntEnv(name, defaultValue, min, max) {
  const raw = process.env[name];
  if (raw === undefined || raw === null || raw === '') {
    return defaultValue;
  }
  const parsed = parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    return defaultValue;
  }
  return parsed;
}

const CONFIG = {
  PORT: parseIntEnv('PORT', 3000, 1, 65535),
  BODY_LIMIT: process.env.BODY_LIMIT || '50mb',
  MAX_MESSAGE_LENGTH: parseIntEnv('MAX_MESSAGE_LENGTH', 100000, 1, 1000000),
  RATE_LIMIT_WINDOW_MS: parseIntEnv('RATE_LIMIT_WINDOW_MS', 60000, 1000, 3600000),
  RATE_LIMIT_MAX: parseIntEnv('RATE_LIMIT_MAX', 100, 1, 10000),
  // Long-running agent tasks need multi-minute budgets; keep under Cloudflare's 524 window only when no proxy sits in front.
  AXIOS_TIMEOUT: parseIntEnv('AXIOS_TIMEOUT', 300000, 1000, 600000),
  AXIOS_MAX_SOCKETS: parseIntEnv('AXIOS_MAX_SOCKETS', 50, 1, 1000),
  AXIOS_MAX_FREE_SOCKETS: parseIntEnv('AXIOS_MAX_FREE_SOCKETS', 10, 1, 500),
  AXIOS_KEEPALIVE_TIMEOUT: parseIntEnv('AXIOS_KEEPALIVE_TIMEOUT', 300000, 1000, 600000),
  AXIOS_FREE_SOCKET_TIMEOUT: parseIntEnv('AXIOS_FREE_SOCKET_TIMEOUT', 60000, 1000, 300000),
  AXIOS_IDLE_TIMEOUT: parseIntEnv('AXIOS_IDLE_TIMEOUT', 300000, 1000, 600000),
  MAX_RETRIES: parseIntEnv('MAX_RETRIES', 10, 1, 20),
  MAX_RATE_LIMIT_RETRIES: parseIntEnv('MAX_RATE_LIMIT_RETRIES', 10, 1, 20),
  RETRY_DELAY_MS: parseIntEnv('RETRY_DELAY_MS', 2000, 100, 30000),
  // Hard cap on total request time incl. retries (10 min)
  TOTAL_REQUEST_TIMEOUT_MS: parseIntEnv('TOTAL_REQUEST_TIMEOUT_MS', 600000, 5000, 900000),
  SSE_BUFFER_LIMIT: parseIntEnv('SSE_BUFFER_LIMIT', 10 * 1024 * 1024, 1024, 50 * 1024 * 1024),
  SSE_MAX_EVENT_SIZE: 1024 * 1024, // 1 MB per SSE event
  MODELS_TIMEOUT: parseIntEnv('MODELS_TIMEOUT', 30000, 1000, 60000),
  HTTP_REFERER: sanitizeHeaderValue(process.env.HTTP_REFERER || 'http://localhost:3000'),
  SITE_NAME: sanitizeHeaderValue(process.env.SITE_NAME || 'OpenRouterProxy'),
  // Admin endpoint stricter rate limiting
  ADMIN_RATE_LIMIT_WINDOW_MS: parseIntEnv('ADMIN_RATE_LIMIT_WINDOW_MS', 60000, 1000, 3600000),
  ADMIN_RATE_LIMIT_MAX: parseIntEnv('ADMIN_RATE_LIMIT_MAX', 10, 1, 10000),
  // DNS configuration for resolving OpenRouter API hostname
  // Useful when the container's default DNS is broken (common in Docker on Synology NAS)
  OPENROUTER_DNS_SERVERS: process.env.OPENROUTER_DNS_SERVERS || '',
  DNS_LOOKUP_TIMEOUT_MS: parseIntEnv('DNS_LOOKUP_TIMEOUT_MS', 5000, 1000, 30000),
  // Model failover: JSON array of arrays defining interchangeable model groups
  // e.g. [["modelA","modelB","modelC"]] means modelA fails over to modelB, then modelC
  MODEL_FAILOVER_GROUPS: process.env.MODEL_FAILOVER_GROUPS || '',
  // IDs advertised by GET /v1/models:
  //   'full'       (default) -> exact OpenRouter IDs, e.g. "poolside/laguna-xs-2.1:free"
  //   'normalized' (legacy)  -> provider prefix and ":free" stripped, e.g. "laguna-xs-2.1"
  // Full IDs make the listing lossless: paid/free variants stay distinct and what a client
  // picks from the list is exactly what gets sent upstream. Bare names sent by older
  // clients are still resolved by toOpenRouterModelId().
  MODEL_LIST_IDS: process.env.MODEL_LIST_IDS === 'normalized' ? 'normalized' : 'full',
  // The model ID mapping is rebuilt from OpenRouter's live model list on every start and
  // then refreshed this often (minutes). 0 = only at startup (plus retries if it fails).
  MODEL_MAP_REFRESH_MINUTES: parseIntEnv('MODEL_MAP_REFRESH_MINUTES', 360, 0, 10080),
  // Max model switches per request (0 = unlimited, try all models in the group)
  MAX_MODEL_FAILOVERS: parseIntEnv('MAX_MODEL_FAILOVERS', 0, 0, 100),
  MAX_MESSAGES: parseIntEnv('MAX_MESSAGES', 200, 1, 10000),
  MAX_TOOL_CALLS: parseIntEnv('MAX_TOOL_CALLS', 100, 1, 10000),
  MAX_MODEL_NAME_LENGTH: 200,
};

// Create a DNS resolver instance for OpenRouter requests only (avoid global mutation)
function createDnsResolver() {
  const dnsServersRaw = CONFIG.OPENROUTER_DNS_SERVERS.split(',').map(s => s.trim()).filter(Boolean);
  const validServers = [];

  for (const s of dnsServersRaw) {
    if (!s) continue;
    const ipVersion = net.isIP(s);
    if (ipVersion === 0) {
      console.warn(`[DNS] Ignoring invalid DNS server IP: ${s}`);
      continue;
    }
    if (isPrivateOrInternal(s)) {
      console.warn(`[DNS] Skipping private/reserved DNS server: ${s}`);
      continue;
    }
    validServers.push(s);
  }

  if (validServers.length === 0) {
    return new dns.Resolver(); // Use system defaults (callback-based)
  }

  const resolver = new dns.Resolver();
  resolver.setServers(validServers);
  console.log(`[DNS] Configured custom DNS servers: ${validServers.join(', ')}`);
  return resolver;
}

// Initialize a resolver for use in customLookup
const dnsResolver = createDnsResolver();

// Model ID mapping - built ENTIRELY from OpenRouter's live model list. Nothing is hardcoded.
//  - Rebuilt on every container start (the first fetch is awaited before requests are served).
//  - If that fetch fails, it is retried in the background with backoff until it succeeds.
//  - Refreshed every MODEL_MAP_REFRESH_MINUTES so free models that rotate in/out are tracked.
//  - A failed or empty fetch NEVER wipes the last good mapping; new state is built aside and
//    swapped in whole.
// Until the first successful fetch, model IDs are passed through to OpenRouter untouched.
//
// /v1/models advertises exact OpenRouter IDs by default (MODEL_LIST_IDS=full), so a client
// normally sends an ID that is already exact. The reverse lookup below only exists to resolve
// bare/normalized names sent by older clients, and it is VARIANT-AWARE: free and paid IDs
// live in separate maps so they can never overwrite each other.
let modelIdMapping = new Map();                 // OpenRouter ID -> normalized ID (legacy listing mode)
let modelIdMappingLoaded = false;
let modelIdMappingPromise = null;
let REVERSE_FREE_MODEL_MAPPING = new Map();     // normalized name -> "provider/model:free"
let REVERSE_PAID_MODEL_MAPPING = new Map();     // normalized name -> "provider/model" (non-free)
let KNOWN_OPENROUTER_IDS = new Set();           // exact IDs OpenRouter currently offers
let modelMapTimer = null;
const MODEL_MAP_RETRY_BASE_MS = 5000;           // retry backoff: 5s, 10s, 20s ... capped at 5 min
const MODEL_MAP_RETRY_MAX_MS = 5 * 60 * 1000;

// Split an ID into its bare model name and free flag: "a/b:free" -> { base: "b", isFree: true }
function splitModelId(id) {
  const lastSlash = id.lastIndexOf('/');
  let base = lastSlash !== -1 ? id.slice(lastSlash + 1) : id;
  const isFree = base.endsWith(':free');
  if (isFree) base = base.slice(0, -':free'.length);
  return { base, isFree };
}

/**
 * Build (but do not apply) all mapping state from an OpenRouter model list.
 * @param {Array} models - OpenRouter models array (GET /api/v1/models -> data)
 * @returns {{mapping: Map, known: Set, free: Map, paid: Map}}
 */
function buildModelIdMapping(models) {
  const mapping = new Map();
  const known = new Set();
  const free = new Map();
  const paid = new Map();

  for (const model of models) {
    if (!model || typeof model.id !== 'string' || !model.id) continue;
    const openRouterId = model.id;
    const { base, isFree } = splitModelId(openRouterId);

    mapping.set(openRouterId, base);
    known.add(openRouterId);

    const target = isFree ? free : paid;
    if (!target.has(base)) {
      target.set(base, openRouterId);
    } else if (target.get(base) !== openRouterId) {
      // Same variant, different provider (e.g. two providers ship "foo:free"): first wins
      logInfo('Model ID collision in reverse mapping (keeping existing)', {
        context: 'ModelMapping',
        alias: base,
        existing: target.get(base),
        new: openRouterId
      });
    }
  }
  return { mapping, known, free, paid };
}

// Swap a freshly built mapping in as a whole
function applyModelIdMapping(built) {
  modelIdMapping = built.mapping;
  KNOWN_OPENROUTER_IDS = built.known;
  REVERSE_FREE_MODEL_MAPPING = built.free;
  REVERSE_PAID_MODEL_MAPPING = built.paid;
  modelIdMappingLoaded = true;
}

/**
 * Resolve the model ID a client sent to the exact ID OpenRouter expects.
 *  1. Exact OpenRouter ID (e.g. "poolside/laguna-xs-2.1:free")  -> unchanged.
 *  2. Explicit ":free" (any/unknown prefix, or bare)             -> the ":free" ID only.
 *                                                                  Never downgraded to a paid/bare ID.
 *  3. Qualified ("x/y", no ":free") but not an exact known ID    -> the paid ID only.
 *  4. Bare name (older clients)                                  -> free first, then paid.
 *  Anything unresolved (including everything before the first successful fetch) is passed
 *  through untouched so OpenRouter returns its real error.
 */
function toOpenRouterModelId(model) {
  if (!model || typeof model !== 'string') return model;
  if (KNOWN_OPENROUTER_IDS.has(model)) return model;

  const { base, isFree } = splitModelId(model);
  let resolved;
  let variant = 'free';
  if (isFree) {
    resolved = REVERSE_FREE_MODEL_MAPPING.get(base);
  } else if (model.includes('/')) {
    resolved = REVERSE_PAID_MODEL_MAPPING.get(base);
    variant = 'paid';
  } else {
    resolved = REVERSE_FREE_MODEL_MAPPING.get(base);
    if (!resolved) {
      resolved = REVERSE_PAID_MODEL_MAPPING.get(base);
      variant = 'paid';
    }
  }

  if (!resolved || resolved === model) return model;
  logInfo('Model ID resolved', { context: 'ModelMapping', requested: model, resolved, variant });
  return resolved;
}

/**
 * Fetch OpenRouter's live model list and rebuild the mapping from it.
 * Concurrent callers share one fetch. Throws on failure, leaving the last good mapping intact.
 * @param {string} reason - 'startup' | 'refresh' | 'retry' (for logs)
 * @returns {Promise<Map>} OpenRouter ID -> normalized ID
 */
async function fetchAndBuildModelIdMapping(reason = 'refresh') {
  if (modelIdMappingPromise) {
    return modelIdMappingPromise;
  }

  modelIdMappingPromise = (async () => {
    let tempAxios;
    try {
      // Use a temporary axios instance without auth for model fetching
      tempAxios = axios.create({
        timeout: 10000,
        httpsAgent: new https.Agent({ keepAlive: true, maxSockets: 10, lookup: customLookup }),
      });

      const response = await tempAxios.get('https://openrouter.ai/api/v1/models');
      const list = response.data?.data;
      if (!Array.isArray(list) || list.length === 0) {
        throw new Error('Invalid or empty model list response from OpenRouter');
      }

      const built = buildModelIdMapping(list);
      if (built.known.size === 0) {
        throw new Error('Model list contained no usable model IDs');
      }

      const previous = KNOWN_OPENROUTER_IDS;
      const removed = [...previous].filter(id => !built.known.has(id));
      const added = [...built.known].filter(id => !previous.has(id));
      applyModelIdMapping(built);

      logInfo('Model ID mapping loaded', {
        context: 'ModelMapping',
        reason,
        models: built.known.size,
        freeAliases: built.free.size,
        paidAliases: built.paid.size,
        added: added.length,
        removed: removed.length,
        removedSample: removed.slice(0, 10)
      });
      return modelIdMapping;
    } catch (error) {
      logError(error, { context: 'ModelMapping fetch failed', reason, keptPreviousMapping: modelIdMappingLoaded });
      throw error;
    } finally {
      // Destroy the temporary agent to prevent socket/handle leaks
      if (tempAxios?.defaults?.httpsAgent) {
        try {
          tempAxios.defaults.httpsAgent.destroy();
        } catch {
          // Agent may already be destroyed
        }
      }
    }
  })().finally(() => {
    modelIdMappingPromise = null;
  });

  return modelIdMappingPromise;
}

// Background refresh / retry loop. After a failure it backs off; after a success it waits
// MODEL_MAP_REFRESH_MINUTES (or stops if that is 0). The timer is unref'd so it never keeps
// the process alive during shutdown.
function scheduleModelIdMappingCycle(delayMs, attempt) {
  if (modelMapTimer) clearTimeout(modelMapTimer);
  modelMapTimer = setTimeout(async () => {
    try {
      await fetchAndBuildModelIdMapping(attempt > 0 ? 'retry' : 'refresh');
      const refreshMs = CONFIG.MODEL_MAP_REFRESH_MINUTES * 60 * 1000;
      if (refreshMs > 0) scheduleModelIdMappingCycle(refreshMs, 0);
    } catch {
      // Already logged by fetchAndBuildModelIdMapping; keep serving the last good mapping
      scheduleModelIdMappingCycle(
        Math.min(MODEL_MAP_RETRY_BASE_MS * 2 ** attempt, MODEL_MAP_RETRY_MAX_MS),
        attempt + 1
      );
    }
  }, delayMs);
  modelMapTimer.unref?.();
}

/**
 * Normalize OpenRouter model ID to OpenAI-compatible format (legacy MODEL_LIST_IDS=normalized)
 * @param {string} openRouterId - OpenRouter model ID
 * @returns {string} Normalized model ID
 */
function normalizeModelId(openRouterId) {
  if (!openRouterId || typeof openRouterId !== 'string') {
    return openRouterId;
  }
  if (modelIdMappingLoaded && modelIdMapping.has(openRouterId)) {
    return modelIdMapping.get(openRouterId);
  }
  // e.g., "openai/gpt-4o" -> "gpt-4o", "poolside/laguna-xs-2.1:free" -> "laguna-xs-2.1"
  return splitModelId(openRouterId).base;
}

/**
 * Normalize model object from OpenRouter to OpenAI format
 * @param {Object} model - OpenRouter model object
 * @returns {Object} Normalized model object
 */
function normalizeModelObject(model) {
  if (!model || typeof model !== 'object') {
    return model;
  }
  
  const normalized = JSON.parse(JSON.stringify(model));
  
  // Normalize ID (legacy mode only; default keeps the exact OpenRouter ID)
  if (normalized.id && CONFIG.MODEL_LIST_IDS === 'normalized') {
    normalized.id = normalizeModelId(normalized.id);
  }
  
  // Ensure required OpenAI fields
  if (!normalized.object) {
    normalized.object = 'model';
  }
  
  if (!normalized.owned_by) {
    // Extract owner from original ID
    const lastSlash = (model.id || '').lastIndexOf('/');
    if (lastSlash > 0) {
      normalized.owned_by = (model.id || '').slice(0, lastSlash);
    } else {
      normalized.owned_by = 'openrouter';
    }
  }
  
  // Ensure created timestamp
  if (!normalized.created) {
    normalized.created = Math.floor(Date.now() / 1000);
  }
  
  // Add empty permission array if missing (OpenAI format)
  if (!normalized.permission) {
    normalized.permission = [];
  }
  
  // Add root and parent if missing
  if (!normalized.root && normalized.id) {
    normalized.root = normalized.id;
  }
  if (!normalized.parent) {
    normalized.parent = null;
  }
  
  return normalized;
}

/**
 * Initialize model ID mapping on startup
 */
async function initializeModelIdMapping() {
  try {
    // Rebuild from the live list on every start; the first fetch is awaited so the mapping
    // is ready before requests are served.
    await fetchAndBuildModelIdMapping('startup');
    const refreshMs = CONFIG.MODEL_MAP_REFRESH_MINUTES * 60 * 1000;
    if (refreshMs > 0) scheduleModelIdMappingCycle(refreshMs, 0);
  } catch (error) {
    logError(error, { context: 'ModelMapping init failed (will retry in background)' });
    scheduleModelIdMappingCycle(MODEL_MAP_RETRY_BASE_MS, 1);
  }
}

/**
 * Normalize error response to OpenAI format
 * @param {Object} error - Error from OpenRouter or internal
 * @param {number} statusCode - HTTP status code
 * @returns {Object} Normalized error response
 */
function normalizeErrorResponse(error, statusCode = 500, { exposeDetails = false } = {}) {
  // OpenAI error types mapping
  const errorTypeMap = {
    400: 'invalid_request_error',
    401: 'authentication_error',
    403: 'permission_error',
    404: 'not_found_error',
    429: 'rate_limit_error',
    500: 'server_error',
    502: 'server_error',
    503: 'server_error',
    504: 'server_error',
  };
  
  let message = 'Internal server error';
  let type = errorTypeMap[statusCode] || 'server_error';
  let param = null;
  let code = null;
  
  if (error) {
    // Extract message from various error formats
    // Axios error shape: error.response.data.error.message
    if (error.response?.data?.error?.message) {
      message = error.response.data.error.message;
    } else if (error.response?.data?.message) {
      message = error.response.data.message;
    } else if (error.error && error.error.message) {
      message = error.error.message;
    } else if (error.message) {
      message = error.message;
    } else if (typeof error === 'string') {
      message = error;
    }
    
    // Extract type from OpenRouter error
    if (error.response?.data?.error?.type) {
      type = error.response.data.error.type;
    } else if (error.error && error.error.type) {
      type = error.error.type;
    } else if (error.type) {
      type = error.type;
    }
    
    // Extract param and code if available
    if (error.response?.data?.error?.param) {
      param = error.response.data.error.param;
    } else if (error.error && error.error.param) {
      param = error.error.param;
    } else if (error.param) {
      param = error.param;
    }
    
    if (error.response?.data?.error?.code) {
      code = error.response.data.error.code;
    } else if (error.error && error.error.code) {
      code = error.error.code;
    } else if (error.code) {
      code = error.code;
    }
  }
  
  // Map common OpenRouter error messages to OpenAI types
  const lowerMessage = message.toLowerCase();
  if (lowerMessage.includes('rate limit') || lowerMessage.includes('quota exceeded')) {
    type = 'rate_limit_error';
  } else if (lowerMessage.includes('invalid api key') || lowerMessage.includes('unauthorized') || lowerMessage.includes('authentication')) {
    type = 'authentication_error';
  } else if (lowerMessage.includes('model not found') || lowerMessage.includes('does not exist')) {
    type = 'not_found_error';
  } else if (lowerMessage.includes('invalid request') || lowerMessage.includes('bad request') || lowerMessage.includes('validation')) {
    type = 'invalid_request_error';
  } else if (lowerMessage.includes('context length') || lowerMessage.includes('max tokens') || lowerMessage.includes('too long')) {
    type = 'invalid_request_error';
    param = 'max_tokens';
  }
  
  const sanitizedMessage = exposeDetails
    ? String(message ?? '').replace(/sk-[a-zA-Z0-9_-]{10,}/g, 'sk-***REDACTED***')
    : sanitizeClientMessage(message, statusCode);
  
  const normalizedError = {
    error: {
      message: sanitizedMessage,
      type,
    }
  };
  
  if (param) {
    normalizedError.error.param = param;
  }
  if (code) {
    normalizedError.error.code = code;
  }
  
  return normalizedError;
}

/**
 * Normalize streaming error to OpenAI SSE format
 * @param {Object} error - Error object
 * @param {number} statusCode - HTTP status code
 * @returns {string} SSE formatted error event
 */
/**
 * Sanitize error messages for client-facing responses
 * For 5xx errors, hide internal details; for 4xx errors, redact sensitive patterns
 */
function sanitizeClientMessage(message, statusCode) {
  if (statusCode >= 500) {
    return 'Upstream service error';
  }
  // Coerce to string before redacting to avoid TypeError when upstream
  // error messages are objects, numbers, or null
  const safeMessage = String(message ?? '');
  return safeMessage.replace(/sk-[a-zA-Z0-9_-]{10,}/g, 'sk-***REDACTED***');
}

function normalizeStreamError(error, statusCode = 500) {
  const normalized = normalizeErrorResponse(error, statusCode, { exposeDetails: true });
  return `data: ${JSON.stringify(normalized)}\n\n`;
}

// Map OpenAI error format to Anthropic error format
// Map OpenAI finish_reason to Anthropic stop_reason
function mapFinishReason(finishReason) {
  const mapping = {
    'tool_calls': 'tool_use',
    'function_calls': 'tool_use',
    'length': 'max_tokens',
    'stop': 'end_turn',
    'content_filter': 'end_turn',
  };
  return mapping[finishReason] || 'end_turn';
}

// Map OpenAI error format to Anthropic error format
function normalizeAnthropicError(openaiError, statusCode = 500) {
  // For 4xx errors, preserve the message; for 5xx, use generic to avoid leaking internal details
  const message = statusCode >= 500 ? 'Upstream service error' : openaiError.error?.message || 'Unknown error';
  return {
    type: 'error',
    error: {
      type: openaiError.error?.type || 'internal_error',
      message,
    }
  };
}

// Terminal SSE error event for the Anthropic Messages endpoint, used once
// content has already been streamed to the client and a retry/failover is
// no longer safe. Anthropic's protocol has no [DONE] sentinel — closing the
// response (res.end()) after this is the correct termination signal.
function normalizeAnthropicStreamError(error, statusCode = 500) {
  const normalized = normalizeAnthropicError(
    normalizeErrorResponse(error, statusCode, { exposeDetails: true }),
    statusCode
  );
  return `event: error\ndata: ${JSON.stringify(normalized)}\n\n`;
}

// OpenAI Chat Completions Request Validation
// Validates request against OpenAI API specification
function validateChatCompletionRequest(body) {
  const errors = [];
  
  // Required fields
  if (!body || typeof body !== 'object') {
    errors.push('Request body must be a valid JSON object');
    return { valid: false, errors };
  }
  
  if (!body.model || typeof body.model !== 'string') {
    errors.push('Field "model" is required and must be a string');
  } else if (body.model.length > CONFIG.MAX_MODEL_NAME_LENGTH) {
    errors.push('Field "model" exceeds maximum length');
  }
  
  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    errors.push('Field "messages" is required and must be a non-empty array');
  } else if (body.messages.length > CONFIG.MAX_MESSAGES) {
    errors.push(`messages: exceeds maximum count of ${CONFIG.MAX_MESSAGES}`);
  } else {
    // Validate each message
    body.messages.forEach((msg, index) => {
      if (!msg || typeof msg !== 'object') {
        errors.push(`messages[${index}]: must be an object`);
        return;
      }
      
      // Role validation
      const validRoles = ['system', 'user', 'assistant', 'tool', 'function'];
      if (!msg.role || !validRoles.includes(msg.role)) {
        errors.push(`messages[${index}].role: must be one of ${validRoles.join(', ')}`);
      }
      
      // Content validation - string or array (for multi-modal)
      if (msg.content !== undefined && msg.content !== null) {
        if (typeof msg.content === 'string') {
          if (msg.content.length > CONFIG.MAX_MESSAGE_LENGTH) {
            errors.push(`messages[${index}].content: exceeds maximum length of ${CONFIG.MAX_MESSAGE_LENGTH} characters`);
          }
        } else if (Array.isArray(msg.content)) {
          // Multi-modal content validation
          msg.content.forEach((part, partIndex) => {
            if (!part || typeof part !== 'object') {
              errors.push(`messages[${index}].content[${partIndex}]: must be an object`);
              return;
            }
            if (part.type === 'text') {
              if (typeof part.text !== 'string') {
                errors.push(`messages[${index}].content[${partIndex}].text: must be a string`);
              } else if (part.text.length > CONFIG.MAX_MESSAGE_LENGTH) {
                errors.push(`messages[${index}].content[${partIndex}].text: exceeds maximum length`);
              }
            } else if (part.type === 'image_url') {
              if (!part.image_url || typeof part.image_url.url !== 'string') {
                errors.push(`messages[${index}].content[${partIndex}].image_url.url: must be a string`);
              } else if (!validateImageUrl(part.image_url.url)) {
                errors.push(`messages[${index}].content[${partIndex}].image_url.url: must be a valid HTTP(S) URL and must not point to private or internal addresses`);
              }
            } else {
              errors.push(`messages[${index}].content[${partIndex}].type: must be "text" or "image_url"`);
            }
          });
        } else {
          errors.push(`messages[${index}].content: must be a string or array`);
        }
      } else if (msg.role !== 'assistant' || !msg.tool_calls) {
        // Content is required unless it's an assistant message with tool_calls
        errors.push(`messages[${index}].content: is required`);
      }
      
      // Tool calls validation (for assistant messages)
      if (msg.tool_calls) {
        if (!Array.isArray(msg.tool_calls)) {
          errors.push(`messages[${index}].tool_calls: must be an array`);
        } else {
          msg.tool_calls.forEach((tc, tcIndex) => {
            if (!tc.id || typeof tc.id !== 'string') {
              errors.push(`messages[${index}].tool_calls[${tcIndex}].id: must be a string`);
            }
            if (tc.type !== 'function') {
              errors.push(`messages[${index}].tool_calls[${tcIndex}].type: must be "function"`);
            }
            if (!tc.function || typeof tc.function !== 'object') {
              errors.push(`messages[${index}].tool_calls[${tcIndex}].function: must be an object`);
            } else {
              if (!tc.function.name || typeof tc.function.name !== 'string') {
                errors.push(`messages[${index}].tool_calls[${tcIndex}].function.name: must be a string`);
              }
              if (tc.function.arguments !== undefined && typeof tc.function.arguments !== 'string') {
                errors.push(`messages[${index}].tool_calls[${tcIndex}].function.arguments: must be a JSON string`);
              }
            }
          });
        }
      }
      
      // Tool call ID validation (for tool role messages)
      if (msg.role === 'tool' && (!msg.tool_call_id || typeof msg.tool_call_id !== 'string')) {
        errors.push(`messages[${index}].tool_call_id: required for tool role messages`);
      }
    });
  }
  
  // Optional parameter validations
  if (body.temperature !== undefined) {
    const temp = Number(body.temperature);
    if (isNaN(temp) || temp < 0 || temp > 2) {
      errors.push('temperature: must be a number between 0 and 2');
    }
  }
  
  if (body.top_p !== undefined) {
    const topP = Number(body.top_p);
    if (isNaN(topP) || topP < 0 || topP > 1) {
      errors.push('top_p: must be a number between 0 and 1');
    }
  }
  
  if (body.max_tokens !== undefined) {
    const maxTokens = Number(body.max_tokens);
    if (!Number.isInteger(maxTokens) || maxTokens <= 0) {
      errors.push('max_tokens: must be a positive integer');
    }
  }
  
  if (body.max_completion_tokens !== undefined) {
    const maxCompletionTokens = Number(body.max_completion_tokens);
    if (!Number.isInteger(maxCompletionTokens) || maxCompletionTokens <= 0) {
      errors.push('max_completion_tokens: must be a positive integer');
    }
  }
  
  if (body.stop !== undefined) {
    if (typeof body.stop === 'string') {
      // Valid
    } else if (Array.isArray(body.stop)) {
      if (body.stop.length > 4) {
        errors.push('stop: array must have at most 4 elements');
      }
      if (!body.stop.every(s => typeof s === 'string')) {
        errors.push('stop: array elements must be strings');
      }
    } else {
      errors.push('stop: must be a string or array of strings');
    }
  }
  
  if (body.presence_penalty !== undefined) {
    const pp = Number(body.presence_penalty);
    if (isNaN(pp) || pp < -2 || pp > 2) {
      errors.push('presence_penalty: must be a number between -2 and 2');
    }
  }
  
  if (body.frequency_penalty !== undefined) {
    const fp = Number(body.frequency_penalty);
    if (isNaN(fp) || fp < -2 || fp > 2) {
      errors.push('frequency_penalty: must be a number between -2 and 2');
    }
  }
  
  if (body.logit_bias !== undefined) {
    if (typeof body.logit_bias !== 'object' || body.logit_bias === null) {
      errors.push('logit_bias: must be an object');
    } else {
      for (const [key, value] of Object.entries(body.logit_bias)) {
        if (!/^-?\d+$/.test(key) || !Number.isInteger(Number(value)) || Number(value) < -100 || Number(value) > 100) {
          errors.push('logit_bias: keys must be token IDs (integers), values must be integers between -100 and 100');
          break;
        }
      }
    }
  }
  
  if (body.user !== undefined && typeof body.user !== 'string') {
    errors.push('user: must be a string');
  }
  
  if (body.seed !== undefined) {
    const seed = Number(body.seed);
    if (!Number.isInteger(seed)) {
      errors.push('seed: must be an integer');
    }
  }
  
  if (body.logprobs !== undefined && typeof body.logprobs !== 'boolean') {
    errors.push('logprobs: must be a boolean');
  }
  
  if (body.top_logprobs !== undefined) {
    const tlp = Number(body.top_logprobs);
    if (!Number.isInteger(tlp) || tlp < 0 || tlp > 20) {
      errors.push('top_logprobs: must be an integer between 0 and 20');
    }
  }
  
  if (body.response_format !== undefined) {
    if (typeof body.response_format !== 'object' || body.response_format === null) {
      errors.push('response_format: must be an object');
    } else if (!body.response_format.type || !['text', 'json_object', 'json_schema'].includes(body.response_format.type)) {
      errors.push('response_format.type: must be "text", "json_object", or "json_schema"');
    } else if (body.response_format.type === 'json_schema') {
      if (!body.response_format.json_schema || typeof body.response_format.json_schema !== 'object') {
        errors.push('response_format.json_schema: required when type is "json_schema"');
      }
    }
  }
  
  if (body.n !== undefined) {
    const n = Number(body.n);
    if (!Number.isInteger(n) || n < 1 || n > 128) {
      errors.push('n: must be an integer between 1 and 128');
    }
  }
  
  if (body.stream !== undefined && typeof body.stream !== 'boolean') {
    errors.push('stream: must be a boolean');
  }
  
  // Tools validation
  if (body.tools !== undefined) {
    if (!Array.isArray(body.tools)) {
      errors.push('tools: must be an array');
    } else if (body.tools.length > CONFIG.MAX_TOOL_CALLS) {
      errors.push(`tools: exceeds maximum count of ${CONFIG.MAX_TOOL_CALLS}`);
    } else {
      body.tools.forEach((tool, toolIndex) => {
        if (!tool || typeof tool !== 'object') {
          errors.push(`tools[${toolIndex}]: must be an object`);
          return;
        }
        if (tool.type !== 'function') {
          errors.push(`tools[${toolIndex}].type: must be "function"`);
        }
        if (!tool.function || typeof tool.function !== 'object') {
          errors.push(`tools[${toolIndex}].function: must be an object`);
        } else {
          if (!tool.function.name || typeof tool.function.name !== 'string') {
            errors.push(`tools[${toolIndex}].function.name: must be a string`);
          }
          if (tool.function.parameters !== undefined && (typeof tool.function.parameters !== 'object' || tool.function.parameters === null)) {
            errors.push(`tools[${toolIndex}].function.parameters: must be a JSON Schema object`);
          }
        }
      });
    }
  }
  
  // Tool choice validation
  if (body.tool_choice !== undefined) {
    if (typeof body.tool_choice === 'string') {
      if (!['none', 'auto', 'required'].includes(body.tool_choice)) {
        errors.push('tool_choice: string must be "none", "auto", or "required"');
      }
    } else if (typeof body.tool_choice === 'object') {
      if (body.tool_choice.type !== 'function' || !body.tool_choice.function || typeof body.tool_choice.function.name !== 'string') {
        errors.push('tool_choice: object must have type="function" and function.name string');
      }
    } else {
      errors.push('tool_choice: must be a string or object');
    }
  }
  
  // Functions (deprecated) validation
  if (body.functions !== undefined) {
    if (!Array.isArray(body.functions)) {
      errors.push('functions: must be an array (deprecated, use tools instead)');
    } else {
      body.functions.forEach((fn, fnIndex) => {
        if (!fn || typeof fn !== 'object') {
          errors.push(`functions[${fnIndex}]: must be an object`);
          return;
        }
        if (!fn.name || typeof fn.name !== 'string') {
          errors.push(`functions[${fnIndex}].name: must be a string`);
        }
        if (fn.parameters !== undefined && (typeof fn.parameters !== 'object' || fn.parameters === null)) {
          errors.push(`functions[${fnIndex}].parameters: must be a JSON Schema object`);
        }
      });
    }
  }
  
  if (body.function_call !== undefined) {
    if (typeof body.function_call === 'string') {
      if (!['none', 'auto'].includes(body.function_call)) {
        errors.push('function_call: string must be "none" or "auto" (deprecated, use tool_choice instead)');
      }
    } else if (typeof body.function_call === 'object') {
      if (!body.function_call.name || typeof body.function_call.name !== 'string') {
        errors.push('function_call: object must have name string (deprecated, use tool_choice instead)');
      }
    } else {
      errors.push('function_call: must be a string or object (deprecated, use tool_choice instead)');
    }
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

// Create logs directory
const __dirname = dirname(fileURLToPath(import.meta.url));
const logsDir = join(__dirname, 'logs');
try {
  await mkdir(logsDir, { recursive: true });
} catch (error) {
  console.error('Error creating logs directory:', error);
}

// Custom DNS lookup function with timeout to prevent indefinite hangs during DNS resolution
// (DNS resolution is not bounded by the axios timeout, so it needs its own safeguard)
const customLookup = (hostname, options, callback) => {
  const isAll = options?.all || false;
  let called = false;
  const callbackOnce = (err, result, family) => {
    if (!called) {
      called = true;
      callback(err, result, family);
    }
  };

  const timeout = setTimeout(() => {
    if (!called) {
      const err = new Error(`DNS lookup timed out for ${hostname} after ${CONFIG.DNS_LOOKUP_TIMEOUT_MS}ms`);
      err.code = 'DNS_LOOKUP_TIMEOUT';
      callbackOnce(err);
    }
  }, CONFIG.DNS_LOOKUP_TIMEOUT_MS);

  // Use the scoped resolver to avoid global DNS mutation
  dnsResolver.resolve(hostname, (err, addresses) => {
    clearTimeout(timeout);
    if (err) {
      callbackOnce(err);
    } else {
      const isAll = options?.all || false;
      if (isAll) {
        const result = addresses.map(addr => ({
          address: addr,
          family: net.isIP(addr) === 6 ? 6 : 4
        }));
        callbackOnce(null, result);
      } else {
        callbackOnce(null, addresses[0], net.isIP(addresses[0]) === 6 ? 6 : 4);
      }
    }
  });
};

// Create axios instance with connection pooling
const keepaliveAgent = new https.Agent({
  keepAlive: true,
  maxSockets: CONFIG.AXIOS_MAX_SOCKETS,
  maxFreeSockets: CONFIG.AXIOS_MAX_FREE_SOCKETS,
  timeout: CONFIG.AXIOS_KEEPALIVE_TIMEOUT,
  freeSocketTimeout: CONFIG.AXIOS_FREE_SOCKET_TIMEOUT,
  // New: Set idle timeout to prevent upstream idle timeout
  keepAliveMsecs: CONFIG.AXIOS_IDLE_TIMEOUT,
  lookup: customLookup,
});

const axiosInstance = axios.create({
  httpsAgent: keepaliveAgent,
  timeout: CONFIG.AXIOS_TIMEOUT,
  // New: HTTP agent with idle timeout for HTTP connections
  httpAgent: new http.Agent({ 
    keepAlive: true, 
    maxSockets: CONFIG.AXIOS_MAX_SOCKETS,
    keepAliveMsecs: CONFIG.AXIOS_IDLE_TIMEOUT,
    lookup: customLookup,
  }),
});

const app = express();

// Reduce body limit to prevent DoS
app.use(express.json({ limit: CONFIG.BODY_LIMIT }));

// Rate limiting middleware (100 requests per minute per IP)
const limiter = rateLimit({
  windowMs: CONFIG.RATE_LIMIT_WINDOW_MS,
  max: CONFIG.RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { message: 'Too many requests, please try again later', type: 'rate_limit_exceeded' } }
});
app.use(limiter);

// Admin endpoint stricter rate limiting (10 requests per minute per IP)
const adminLimiter = rateLimit({
  windowMs: CONFIG.ADMIN_RATE_LIMIT_WINDOW_MS,
  max: CONFIG.ADMIN_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { message: 'Too many admin requests, please try again later', type: 'rate_limit_exceeded' } }
});

// Security headers middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // CSP header removed - not needed for API-only service
  next();
});

app.use(requestLoggingMiddleware);

// Initialize with default key(s) if provided
const initializeKeys = async () => {
  const defaultKeys = process.env.OPENROUTER_API_KEYS;
  if (defaultKeys) {
    // Support comma-separated multiple keys
    const keys = defaultKeys.split(',').map(k => k.trim()).filter(k => k);
    for (const key of keys) {
      await keyManager.addKey(key);
    }
  }
  await keyManager.initialize();
};

let isReady = false;
// Wait for initialization before accepting requests
try {
  await Promise.all([initializeKeys(), initializeModelIdMapping(), failoverManager.initialize()]);
  isReady = true;
} catch (error) {
  logError(error, { context: 'Key initialization' });
  console.error('Failed to initialize keys, exiting...');
  process.exit(1);
}

// Admin authentication middleware
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const adminAuth = (req, res, next) => {
  if (!ADMIN_SECRET) {
    return res.status(503).json({ error: 'Admin secret not configured' });
  }
  const provided = req.headers['x-admin-secret'] || '';
  const providedBuf = Buffer.from(provided);
  const secretBuf = Buffer.from(ADMIN_SECRET);
  if (providedBuf.length !== secretBuf.length || !timingSafeEqual(providedBuf, secretBuf)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

// Admin endpoint to add new API keys
app.post('/admin/keys', adminLimiter, adminAuth, async (req, res) => {
  try {
    const { key } = req.body;
    if (!key) {
      return res.status(400).json({ error: 'API key is required' });
    }
    await keyManager.addKey(key);
    res.json({ message: 'API key added successfully' });
  } catch (error) {
    logError(error, { context: 'Admin API key addition' });
    res.status(500).json({ error: error.message });
  }
});

// Helper function to handle streaming response
async function handleStreamingResponse(axiosResponse, req, res, abortController) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const MAX_BUFFER_SIZE = CONFIG.SSE_BUFFER_LIMIT;
  const MAX_EVENT_SIZE = CONFIG.SSE_MAX_EVENT_SIZE;
  let buffer = '';
  let nvidiaRateLimitDetected = false;
  let clientClosed = false;

  // Use AbortController to abort upstream request on client disconnect
  req.once('close', () => {
    clientClosed = true;
    axiosResponse.data.destroy();
    abortController.abort();
  });

  // Optimized SSE parser - processes buffer incrementally
  const processBuffer = () => {
    let processed = false;
    while (true) {
      const delimiterIndex = buffer.indexOf('\n\n');
      if (delimiterIndex === -1) break;
      
      const event = buffer.slice(0, delimiterIndex);
      buffer = buffer.slice(delimiterIndex + 2);
      processed = true;
      
      // Check per-event size limit
      if (event.length > MAX_EVENT_SIZE) {
        logError(new Error('SSE event exceeded maximum size'), { 
          context: 'Stream', 
          eventSize: event.length 
        });
        if (!res.writableEnded) {
          res.write(`data: ${JSON.stringify({
            error: {
              message: 'Event too large',
              type: 'stream_error'
            }
          })}\n\n`);
          res.write('data: [DONE]\n\n');
          res.end();
        }
        axiosResponse.data.destroy();
        abortController.abort();
        return true; // indicates error handled
      }
      
      // Process the event
      if (event.startsWith('data: ')) {
        const dataStr = event.slice(6).trim();
        
        if (dataStr === '[DONE]') {
          res.write(event + '\n\n');
          continue;
        }
        
        try {
          const data = JSON.parse(dataStr);
          
          if (data.error && data.error.message) {
            const errorMsg = data.error.message;
            const isRateLimit = KeyManager.isRateLimitError({
              response: { data: data, status: 200, headers: {} }
            });
            if (typeof errorMsg === 'string' && isRateLimit) {
              nvidiaRateLimitDetected = true;
              logInfo('Rate limit detected in SSE chunk', { 
                context: 'Stream', 
                errorMessage: errorMsg 
              });
              return true; // signal to break outer loop
            }
          }
        } catch (e) {
          // Not valid JSON, just forward it
        }
      }
      
      // Write the event to client
      res.write(event + '\n\n');
    }
    return false;
  };

  for await (const chunk of axiosResponse.data) {
    if (clientClosed) {
      break;
    }
    
    const chunkStr = chunk.toString();
    buffer += chunkStr;
    
    // Prevent unbounded buffer growth
    if (buffer.length > MAX_BUFFER_SIZE) {
      logError(new Error('SSE buffer exceeded maximum size'), { 
        context: 'Stream', 
        bufferSize: buffer.length 
      });
      // Send error event and close cleanly
      if (!res.writableEnded) {
        res.write(`data: ${JSON.stringify({
          error: {
            message: 'SSE buffer exceeded maximum size',
            type: 'stream_error'
          }
        })}\n\n`);
        res.write('data: [DONE]\n\n');
        res.end();
      }
      axiosResponse.data.destroy();
      abortController.abort();
      return;
    }
    
    // Process complete events incrementally
    const errorHandled = processBuffer();
    if (errorHandled) {
      break;
    }
    
    if (nvidiaRateLimitDetected) {
      break;
    }
  }
  
  // Process any remaining buffer
  if (!clientClosed && !nvidiaRateLimitDetected) {
    processBuffer();
  }
  
  if (nvidiaRateLimitDetected) {
    // Destroy the upstream stream and abort the controller before throwing
    // to prevent socket/stream leaks on NVIDIA rate-limit paths
    try { axiosResponse.data.destroy(); } catch {}
    try { abortController.abort(); } catch {}
    const error = new Error('NVIDIA rate limit exceeded');
    error.isNvidiaRateLimit = true;
    throw error;
  }
  
  // Write any remaining buffer
  if (buffer && !res.writableEnded) {
    res.write(buffer);
  }
  
  if (!res.writableEnded) {
    res.end();
  }
}

// Convert an OpenRouter/OpenAI streaming chat-completion into Anthropic
// Messages streaming events (message_start / content_block_* / message_delta
// / message_stop) and forward them to the client as they arrive. The two
// APIs' SSE formats are not compatible, so every event is re-encoded rather
// than passed through — contrast with handleStreamingResponse above, which
// proxies OpenAI-format bytes unchanged.
//
// Resolves normally on a clean completion (message_stop already sent, res
// already ended). Throws on any problem detected while reading the upstream
// stream; the caller decides whether that's still safe to retry/fail over
// by checking whether anything was actually written to the client response
// (tracked externally, the same way handleStreamingResponse's callers do).
async function handleAnthropicStreamingResponse(axiosResponse, req, res, abortController, { requestId, model }) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const MAX_BUFFER_SIZE = CONFIG.SSE_BUFFER_LIMIT;
  const MAX_EVENT_SIZE = CONFIG.SSE_MAX_EVENT_SIZE;
  let buffer = '';
  let clientClosed = false;

  req.once('close', () => {
    clientClosed = true;
    axiosResponse.data.destroy();
    abortController.abort();
  });

  const messageId = `msg_${requestId.replace(/-/g, '')}`;
  let messageStarted = false;
  let usage = { input_tokens: 0, output_tokens: 0 };
  let stopReason = 'end_turn';
  let nextBlockIndex = 0;
  let textBlockIndex = null;
  const toolBlocks = new Map(); // openaiIndex -> { blockIndex, started }

  const sendEvent = (type, data) => res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`);

  const ensureMessageStart = () => {
    if (messageStarted) return;
    messageStarted = true;
    sendEvent('message_start', {
      type: 'message_start',
      message: {
        id: messageId, type: 'message', role: 'assistant', model,
        content: [], stop_reason: null, stop_sequence: null, usage
      }
    });
  };

  const ensureTextBlock = () => {
    ensureMessageStart();
    if (textBlockIndex === null) {
      textBlockIndex = nextBlockIndex++;
      sendEvent('content_block_start', {
        type: 'content_block_start', index: textBlockIndex,
        content_block: { type: 'text', text: '' }
      });
    }
    return textBlockIndex;
  };

  const ensureToolBlock = (openaiIndex, id, name) => {
    ensureMessageStart();
    let entry = toolBlocks.get(openaiIndex);
    if (!entry) {
      entry = { blockIndex: nextBlockIndex++, started: false };
      toolBlocks.set(openaiIndex, entry);
    }
    if (!entry.started) {
      entry.started = true;
      sendEvent('content_block_start', {
        type: 'content_block_start', index: entry.blockIndex,
        content_block: { type: 'tool_use', id: id || `toolu_${requestId}_${openaiIndex}`, name: name || '', input: {} }
      });
    }
    return entry.blockIndex;
  };

  const handleChunk = (data) => {
    ensureMessageStart();
    if (data.usage) {
      usage = {
        input_tokens: data.usage.prompt_tokens ?? usage.input_tokens,
        output_tokens: data.usage.completion_tokens ?? usage.output_tokens,
      };
    }
    const choice = data.choices?.[0];
    if (!choice) return;
    const delta = choice.delta || {};

    if (typeof delta.content === 'string' && delta.content.length > 0) {
      const idx = ensureTextBlock();
      sendEvent('content_block_delta', { type: 'content_block_delta', index: idx, delta: { type: 'text_delta', text: delta.content } });
    }

    if (Array.isArray(delta.tool_calls)) {
      for (const tc of delta.tool_calls) {
        const openaiIndex = tc.index ?? 0;
        const idx = ensureToolBlock(openaiIndex, tc.id, tc.function?.name);
        const argsFragment = tc.function?.arguments;
        if (typeof argsFragment === 'string' && argsFragment.length > 0) {
          sendEvent('content_block_delta', { type: 'content_block_delta', index: idx, delta: { type: 'input_json_delta', partial_json: argsFragment } });
        }
      }
    }

    if (choice.finish_reason) {
      stopReason = mapFinishReason(choice.finish_reason);
    }
  };

  // Returns 'ratelimit' | 'error' | null (null = processed normally)
  const processBuffer = () => {
    while (true) {
      const delimiterIndex = buffer.indexOf('\n\n');
      if (delimiterIndex === -1) break;
      const event = buffer.slice(0, delimiterIndex);
      buffer = buffer.slice(delimiterIndex + 2);

      if (event.length > MAX_EVENT_SIZE) {
        logError(new Error('SSE event exceeded maximum size'), { context: 'Anthropic stream', eventSize: event.length });
        return 'error';
      }
      if (!event.startsWith('data: ')) continue;
      const dataStr = event.slice(6).trim();
      if (dataStr === '[DONE]') continue;

      let data;
      try { data = JSON.parse(dataStr); } catch { continue; }

      if (data.error && data.error.message) {
        const isRateLimit = KeyManager.isRateLimitError({ response: { data, status: 200, headers: {} } });
        logInfo(isRateLimit ? 'Rate limit detected in SSE chunk' : 'Upstream error in SSE chunk', {
          context: 'Anthropic stream', errorMessage: String(data.error.message).substring(0, 200)
        });
        return isRateLimit ? 'ratelimit' : 'error';
      }

      handleChunk(data);
    }
    return null;
  };

  let stopSignal = null;
  for await (const chunk of axiosResponse.data) {
    if (clientClosed) break;
    buffer += chunk.toString();
    if (buffer.length > MAX_BUFFER_SIZE) {
      logError(new Error('SSE buffer exceeded maximum size'), { context: 'Anthropic stream', bufferSize: buffer.length });
      stopSignal = 'error';
      break;
    }
    stopSignal = processBuffer();
    if (stopSignal) break;
  }
  if (!clientClosed && !stopSignal) {
    stopSignal = processBuffer();
  }

  if (clientClosed) return;

  if (stopSignal === 'ratelimit' || stopSignal === 'error') {
    try { axiosResponse.data.destroy(); } catch {}
    try { abortController.abort(); } catch {}
    const error = new Error(stopSignal === 'ratelimit' ? 'Rate limit mid-stream' : 'Upstream error mid-stream');
    if (stopSignal === 'ratelimit') error.isRateLimit = true;
    throw error;
  }

  // Clean completion
  if (textBlockIndex !== null) {
    sendEvent('content_block_stop', { type: 'content_block_stop', index: textBlockIndex });
  }
  for (const entry of toolBlocks.values()) {
    if (entry.started) sendEvent('content_block_stop', { type: 'content_block_stop', index: entry.blockIndex });
  }
  ensureMessageStart(); // guarantee message_start even on a genuinely empty response
  sendEvent('message_delta', {
    type: 'message_delta',
    delta: { stop_reason: stopReason, stop_sequence: null },
    usage: { output_tokens: usage.output_tokens }
  });
  sendEvent('message_stop', { type: 'message_stop' });
  if (!res.writableEnded) res.end();
}

// OpenRouter proxy endpoint
app.post('/v1/chat/completions', async (req, res) => {
  // Validate request against OpenAI Chat Completions schema
  const validation = validateChatCompletionRequest(req.body);
  if (!validation.valid) {
    return res.status(400).json({
      error: {
        message: validation.errors.join('; '),
        type: 'invalid_request_error'
      }
    });
  }
  
  const requestId = randomUUID();
  // Use higher retry limit for rate limit errors (which are most common)
  const maxRetries = CONFIG.MAX_RATE_LIMIT_RETRIES;
  const isStreaming = req.body?.stream === true;

  // Model failover: build chain of interchangeable models.
  // The system tries other API accounts first (full retry cycle per model)
  // before switching to the next model in the failover group.
  const originalModel = req.body.model;
  const failoverChain = failoverManager.getFailoverChain(originalModel) || [originalModel];
  const maxFailoverSwitches = failoverManager.getMaxFailoverSwitches();
  const requestStartTime = Date.now();

  let activeAbortController = null;
  req.once('close', () => activeAbortController?.abort());

  for (let modelIdx = 0; modelIdx < failoverChain.length; modelIdx++) {
    const currentFailoverModel = failoverChain[modelIdx];

    if (modelIdx > 0) {
      if (maxFailoverSwitches > 0 && modelIdx > maxFailoverSwitches) {
        return res.status(503).json(normalizeErrorResponse(
          'Max model failover attempts exceeded — all models unavailable',
          503
        ));
      }
      failoverManager.logFailover(originalModel, currentFailoverModel, requestId);
      res.setHeader('X-Failover-Model', 'true');
    }

    let retryCount = 0;
    let streamDataSent = false;
    let innerLoopError = null;
    let innerLoopStatusCode = null;
    let requestBody;
    let toolsStripped = false;

    while (retryCount < maxRetries) {
      // Check total elapsed time to prevent Cloudflare 524 timeout (100s limit)
      const elapsedMs = Date.now() - requestStartTime;
    if (elapsedMs >= CONFIG.TOTAL_REQUEST_TIMEOUT_MS) {
      logError(new Error('Total request timeout exceeded'), {
        context: 'Chat completions',
        elapsedMs,
        timeoutMs: CONFIG.TOTAL_REQUEST_TIMEOUT_MS,
        retryCount
      });
      return res.status(504).json(normalizeErrorResponse(
        'Request timeout: total processing time exceeded limit',
        504
      ));
    }
    try {
      // Get the current key or rotate if needed
      const currentKey = await keyManager.getKey();
      
      // Create AbortController for client disconnect handling
      activeAbortController = new AbortController();
      const abortController = activeAbortController;
      
      // Forward client headers if provided, fallback to env vars
      const clientReferer = req.headers['http-referer'] || req.headers['referer'];
      const clientTitle = req.headers['x-title'];
      
      // Cap per-request timeout to remaining total budget to prevent exceeding Cloudflare 100s
      const remainingMs = CONFIG.TOTAL_REQUEST_TIMEOUT_MS - (Date.now() - requestStartTime);
      const axiosConfig = {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${currentKey}`,
          'HTTP-Referer': sanitizeHeaderValue(clientReferer || CONFIG.HTTP_REFERER),
          'X-Title': sanitizeHeaderValue(clientTitle || CONFIG.SITE_NAME),
          ...forwardedAttributionHeaders(req),
          'X-Request-ID': requestId
        },
        timeout: Math.max(100, Math.min(CONFIG.AXIOS_TIMEOUT, remainingMs)),
        signal: createAbortSignal(abortController, remainingMs)
      };

      // Add responseType: 'stream' for streaming requests
      if (isStreaming) {
        axiosConfig.responseType = 'stream';
      }

      // Convert normalized model ID back to OpenRouter ID if needed
      // Use the current failover model (may differ from original request model)
      requestBody = { ...req.body };
      if (toolsStripped) {
        delete requestBody.tools;
        delete requestBody.tool_choice;
      }
      // Exact OpenRouter IDs pass through; advertised/normalized names are resolved (variant-aware)
      requestBody.model = toOpenRouterModelId(currentFailoverModel);

      const response = await axiosInstance.post(
        'https://openrouter.ai/api/v1/chat/completions',
        requestBody,
        axiosConfig
      );

      // Check for error in response body (OpenRouter returns 200 with error in body for model errors)
      const responseData = response.data;
      if (responseData?.error?.message) {
        const errorMessage = responseData.error.message;
        
        // Use centralized rate limit detection (handles NVIDIA, Xiaomi MiMo, and generic)
        const isRateLimit = KeyManager.isRateLimitError({
          response: {
            data: responseData,
            status: 200,
            headers: response.headers
          }
        });
        
        if (isRateLimit) {
          logInfo('Rate limit detected in response', { 
            context: 'Response', 
            errorMessage: errorMessage.substring(0, 200) 
          });
          // Create an error that will be caught by the catch block
          const error = new Error('Rate limit in response');
          error.response = {
            data: responseData,
            status: 200,
            headers: response.headers
          };
          error.isRateLimit = true;
          throw error;
        }
        
        // For other errors (validation, model not found, etc.), check if failoverable
        const statusCode = response.status || 400;
        if (failoverManager.shouldFailover({ response: { status: statusCode, data: responseData } })) {
          innerLoopError = new Error('OpenRouter error in response body');
          innerLoopError.response = { status: statusCode, data: responseData };
          innerLoopStatusCode = statusCode;
          break;
        }
        return res.status(statusCode).json(normalizeErrorResponse(responseData, statusCode));
      }

      // Mark the successful use of the key (only on true success, no error in body)
      await keyManager.markKeySuccess();

      // Handle streaming response differently
      if (isStreaming) {
        // Wrap res.write to track if data was sent
        const originalWrite = res.write;
        try {
          res.write = function(chunk) {
            if (chunk && chunk.length > 0) {
              streamDataSent = true;
            }
            return originalWrite.apply(this, arguments);
          };
          
          await handleStreamingResponse(response, req, res, abortController);
          return;
        } finally {
          res.write = originalWrite;
        }
      }

      return res.json(responseData);
    } catch (error) {
      
      const keyRateLimit = await keyManager.markKeyError(error);
      const classified = classifyError(error);
      const isRateLimit = isRateLimitError({ keyRateLimit, classified });
      const retryDelayMs = keyManager.calculateRetryDelay ? keyManager.calculateRetryDelay(retryCount) : CONFIG.RETRY_DELAY_MS;
      const errorMessage = classified.errorMessage;
      const shouldRetryForNetwork = classified.shouldRetryForNetwork;

      // If the client disconnected, do NOT retry — downstream is gone
      if (isClientDisconnect(activeAbortController, classified)) {
        return;
      }

      // Once any bytes have reached the client on this stream, retrying or
      // failing over would corrupt/duplicate output, so from that point a
      // stream error is terminal: forward it and close (with the [DONE]
      // sentinel SSE clients expect). Before that point nothing has been
      // committed to the client yet, so it's safe to fall through to the
      // same retry/failover logic used for non-streaming requests below —
      // the caller just sees the stream start a little later.
      if (isStreaming && streamDataSent) {
        if (!res.writableEnded) {
          const errorForResponse = error?.response?.data || error;
          res.write(normalizeStreamError(errorForResponse, error.response?.status || 500));
          res.write('data: [DONE]\n\n');
          res.end();
        }
        return;
      }

      // Check for 404 "No endpoints found that support tool use" — retry without tools
        // This handles models that don't support function calling
        const isToolCapabilityError = error.response?.status === 404 && errorMessage &&
          errorMessage.toLowerCase().includes('no endpoints found that support') &&
          errorMessage.toLowerCase().includes('tool use');
        const requestHadTools = requestBody && (requestBody.tools || requestBody.tool_choice);

        if (isToolCapabilityError && requestHadTools && retryCount < maxRetries - 1) {
          // Mark that we should strip tools on the next attempt
          toolsStripped = true;
          retryCount++;
          logInfo('Model does not support tools, will retry without tools on next attempt', {
            context: 'Retry',
            model: currentFailoverModel,
            errorMessage: errorMessage.substring(0, 200)
          });
          
          // Continue to next iteration (will retry same model without tools)
          continue;
        }

        // Only retry on rate limits, server errors, network errors, or exhausted keys
        if ((isRateLimit || error.code === 'NO_AVAILABLE_KEYS' || error.response?.status >= 500 || shouldRetryForNetwork) && retryCount < maxRetries - 1) {
        // If we've already spent more time than the total budget, don't retry
        const elapsedBeforeRetry = Date.now() - requestStartTime;
        if (elapsedBeforeRetry >= CONFIG.TOTAL_REQUEST_TIMEOUT_MS) {
          logError(new Error('Total request timeout exceeded before retry'), {
            context: 'Chat completions',
            elapsedMs: elapsedBeforeRetry,
            timeoutMs: CONFIG.TOTAL_REQUEST_TIMEOUT_MS,
            retryCount
          });
          return res.status(504).json(normalizeErrorResponse(
            'Request timeout: total processing time exceeded limit',
            504
          ));
        }
        retryCount++;
        
        // Determine wait time using shared helper (caps at remaining budget)
        const remainingMs = CONFIG.TOTAL_REQUEST_TIMEOUT_MS - (Date.now() - requestStartTime);
        const { waitMs, waitReason, shouldAbort } = calculateRetryDelay({
          error, isRateLimit, retryCount, keyManager, remainingMs, retryDelayMs
        });
        
        if (shouldAbort) {
          return res.status(504).json(normalizeErrorResponse(
            'Request timeout: total processing time exceeded limit',
            504
          ));
        }
        
        // Add delay for rate limits, network errors, or exhausted keys
        if (isRateLimit || error.code === 'NO_AVAILABLE_KEYS' || shouldRetryForNetwork) {
          logRetry('chat completions', { retryCount, maxRetries, waitMs, waitReason, errorCode: error.code, errorMessage });
          await new Promise(resolve => setTimeout(resolve, waitMs));
        }
        continue;
      }

      logError(error, { 
        context: 'Chat completions',
        retryCount,
        statusCode: error.response?.status,
        streaming: isStreaming,
        // Include OpenRouter error response body for debugging 400/5xx errors
        responseData: error.response?.data,
        // Include request details for debugging (sanitized by logger)
        requestModel: currentFailoverModel,
        requestBodyKeys: Object.keys(req.body || {})
      });

      // Store error for outer loop (failover) consideration. For streaming
      // requests this is only reached when nothing has been sent to the
      // client yet (see the streamDataSent check above), so it's safe to
      // let the outer loop try the next model exactly as it does for a
      // non-streaming request.
      innerLoopError = error;
      innerLoopStatusCode = error.response?.status || 500;
      break;
    }
  }
    // End of inner retry loop

    // Inner loop finished without success — check if we can failover
    if (innerLoopError && !res.headersSent && failoverManager.shouldFailover(innerLoopError) && modelIdx < failoverChain.length - 1) {
      continue;
    }

    // No more failover models, or error is not failoverable — return error to client
    if (innerLoopError) {
      // Extract response body from axios errors so the client gets the real OpenRouter error message
      const errorForResponse = innerLoopError?.response?.data || innerLoopError;
      if (isStreaming && !res.writableEnded) {
        res.write(normalizeStreamError(errorForResponse, innerLoopStatusCode));
        res.write('data: [DONE]\n\n');
        res.end();
      } else if (!res.headersSent) {
        return res.status(innerLoopStatusCode).json(normalizeErrorResponse(errorForResponse, innerLoopStatusCode));
      }
      return;
    }
  }
  // End of outer failover loop — all models exhausted
  if (!res.headersSent) {
    return res.status(503).json(normalizeErrorResponse(
      'All models in failover chain exhausted', 503
    ));
  }
});

// Health check endpoint

app.get('/health', (req, res) => {
  res.json({
    status: isReady ? 'ready' : 'not ready',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Models endpoint
app.get('/v1/models', async (req, res) => {
  const requestId = randomUUID();
  // Use higher retry limit for rate limit errors
  const maxRetries = CONFIG.MAX_RATE_LIMIT_RETRIES;
  let retryCount = 0;
  const requestStartTime = Date.now();

  let activeAbortController = null;
  req.once('close', () => activeAbortController?.abort());

  while (retryCount < maxRetries) {
    // Check total elapsed time to prevent Cloudflare 524 timeout (100s limit)
    const elapsedMs = Date.now() - requestStartTime;
    if (elapsedMs >= CONFIG.TOTAL_REQUEST_TIMEOUT_MS) {
      logError(new Error('Total request timeout exceeded'), {
        context: 'Models endpoint',
        elapsedMs,
        timeoutMs: CONFIG.TOTAL_REQUEST_TIMEOUT_MS,
        retryCount
      });
      return res.status(504).json(normalizeErrorResponse(
        'Request timeout: total processing time exceeded limit',
        504
      ));
    }
    try {
      const currentKey = await keyManager.getKey();
      
      // Create AbortController for client disconnect handling
      activeAbortController = new AbortController();
      const abortController = activeAbortController;
      
      // Forward client headers if provided, fallback to env vars
      const clientReferer = req.headers['http-referer'] || req.headers['referer'];
      const clientTitle = req.headers['x-title'];

      const remainingMs = CONFIG.TOTAL_REQUEST_TIMEOUT_MS - (Date.now() - requestStartTime);
      const axiosConfig = {
        headers: {
          'Authorization': `Bearer ${currentKey}`,
          'HTTP-Referer': sanitizeHeaderValue(clientReferer || CONFIG.HTTP_REFERER),
          'X-Title': sanitizeHeaderValue(clientTitle || CONFIG.SITE_NAME),
          'X-Request-ID': requestId
        },
        timeout: Math.max(100, Math.min(CONFIG.MODELS_TIMEOUT, remainingMs)),
        signal: createAbortSignal(abortController, remainingMs)
      };

      const response = await axiosInstance.get(
        'https://openrouter.ai/api/v1/models',
        axiosConfig
      );

      await keyManager.markKeySuccess();
      
      // Normalize model list to OpenAI format
      const responseData = response.data;
      if (responseData && responseData.data && Array.isArray(responseData.data)) {
        responseData.data = responseData.data.map(normalizeModelObject);
      }
      
      return res.json(responseData);
    } catch (error) {
      const keyRateLimit = await keyManager.markKeyError(error);
      const classified = classifyError(error);
      const isRateLimit = isRateLimitError({ keyRateLimit, classified });
      const retryDelayMs = keyManager.calculateRetryDelay ? keyManager.calculateRetryDelay(retryCount) : CONFIG.RETRY_DELAY_MS;
      const errorMessage = classified.errorMessage;
      const shouldRetryForNetwork = classified.shouldRetryForNetwork;

      // If the client disconnected, do NOT retry — downstream is gone
      if (isClientDisconnect(activeAbortController, classified)) {
        return;
      }

      if ((isRateLimit || error.code === 'NO_AVAILABLE_KEYS' || error.response?.status >= 500 || shouldRetryForNetwork) && retryCount < maxRetries - 1) {
        // If we've already spent more time than the total budget, don't retry
        const elapsedBeforeRetry = Date.now() - requestStartTime;
        if (elapsedBeforeRetry >= CONFIG.TOTAL_REQUEST_TIMEOUT_MS) {
          logError(new Error('Total request timeout exceeded before retry'), {
            context: 'Models endpoint',
            elapsedMs: elapsedBeforeRetry,
            timeoutMs: CONFIG.TOTAL_REQUEST_TIMEOUT_MS,
            retryCount
          });
          return res.status(504).json(normalizeErrorResponse(
            'Request timeout: total processing time exceeded limit',
            504
          ));
        }
        retryCount++;
        
        // Determine wait time using shared helper (caps at remaining budget)
        const remainingMs = CONFIG.TOTAL_REQUEST_TIMEOUT_MS - (Date.now() - requestStartTime);
        const { waitMs, waitReason, shouldAbort } = calculateRetryDelay({
          error, isRateLimit, retryCount, keyManager, remainingMs, retryDelayMs
        });
        
        if (shouldAbort) {
          return res.status(504).json(normalizeErrorResponse(
            'Request timeout: total processing time exceeded limit',
            504
          ));
        }
        
        // Add delay for rate limits, network errors, or exhausted keys
        if (isRateLimit || error.code === 'NO_AVAILABLE_KEYS' || shouldRetryForNetwork) {
          logRetry('models', { retryCount, maxRetries, waitMs, waitReason, errorCode: error.code, errorMessage });
          await new Promise(resolve => setTimeout(resolve, waitMs));
        }
        continue;
      }

      logError(error, { 
        context: 'Models endpoint',
        retryCount,
        statusCode: error.response?.status,
        responseData: error.response?.data
      });

      const statusCode = error.response?.status || 500;
      return res.status(statusCode).json(normalizeErrorResponse(error, statusCode));
    }
  }
});

// Anthropic Messages endpoint - translates Anthropic format to OpenAI format for OpenRouter
app.post('/v1/messages', async (req, res) => {
  // Validate request body
  if (!req.body) {
    return res.status(400).json({
      error: { message: 'Request body is required', type: 'invalid_request_error' }
    });
  }
  
  if (!req.body.model || !Array.isArray(req.body.messages) || req.body.messages.length === 0) {
    return res.status(400).json({
      error: { message: 'Invalid request: model and non-empty messages array required', type: 'invalid_request_error' }
    });
  }
  
  if (req.body.max_tokens === undefined || typeof req.body.max_tokens !== 'number' || req.body.max_tokens <= 0) {
    return res.status(400).json({
      error: { message: 'Invalid request: max_tokens is required and must be a positive number', type: 'invalid_request_error' }
    });
  }
  
  const requestId = randomUUID();
  // Use higher retry limit for rate limit errors
  const maxRetries = CONFIG.MAX_RATE_LIMIT_RETRIES;

  const isStreaming = req.body.stream === true;

  // Model failover: build chain of interchangeable models
  const originalModel = req.body.model;
  const failoverChain = failoverManager.getFailoverChain(originalModel) || [originalModel];
  const maxFailoverSwitches = failoverManager.getMaxFailoverSwitches();
  const requestStartTime = Date.now();

  let activeAbortController = null;
  req.once('close', () => activeAbortController?.abort());

  // Transform Anthropic format to OpenAI format
  const baseOpenAIBody = {
    model: req.body.model,
    messages: req.body.messages.map(msg => {
      // Anthropic uses 'user'/'assistant' roles, OpenAI uses 'user'/'assistant'/'system'
      // System message is separate in Anthropic
      if (msg.role === 'system') {
        return { role: 'system', content: msg.content };
      }
      return msg;
    }),
    stream: req.body.stream || false,
    // Ask for a final usage-bearing chunk so the translated Anthropic
    // message_delta event can report real token counts instead of 0.
    ...(req.body.stream ? { stream_options: { include_usage: true } } : {}),
    max_tokens: req.body.max_tokens,
    temperature: req.body.temperature,
    top_p: req.body.top_p,
    stop: req.body.stop_sequences || req.body.stop,
    tools: req.body.tools,
    tool_choice: req.body.tool_choice,
  };

  for (let modelIdx = 0; modelIdx < failoverChain.length; modelIdx++) {
    const currentFailoverModel = failoverChain[modelIdx];

    if (modelIdx > 0) {
      if (maxFailoverSwitches > 0 && modelIdx > maxFailoverSwitches) {
        return res.status(503).json(normalizeErrorResponse(
          'Max model failover attempts exceeded — all models unavailable',
          503
        ));
      }
      failoverManager.logFailover(originalModel, currentFailoverModel, requestId);
      res.setHeader('X-Failover-Model', 'true');
    }

    let retryCount = 0;
    let innerLoopError = null;
    let innerLoopStatusCode = null;
    let streamDataSent = false;

    // Transform Anthropic format to OpenAI format (with current failover model)
    const openAIBody = {
      ...baseOpenAIBody,
      model: currentFailoverModel,
      messages: [...baseOpenAIBody.messages],
    };

    // Add system message if provided (Anthropic has separate system param)
    if (req.body.system) {
      openAIBody.messages.unshift({ role: 'system', content: req.body.system });
    }

    while (retryCount < maxRetries) {
    // Check total elapsed time to prevent Cloudflare 524 timeout (100s limit)
    const elapsedMs = Date.now() - requestStartTime;
    if (elapsedMs >= CONFIG.TOTAL_REQUEST_TIMEOUT_MS) {
      logError(new Error('Total request timeout exceeded'), {
        context: 'Anthropic endpoint',
        elapsedMs,
        timeoutMs: CONFIG.TOTAL_REQUEST_TIMEOUT_MS,
        retryCount
      });
      return res.status(504).json(normalizeErrorResponse(
        'Request timeout: total processing time exceeded limit',
        504
      ));
    }

    try {
      const currentKey = await keyManager.getKey();
      
      // Create AbortController for client disconnect handling
      activeAbortController = new AbortController();
      const abortController = activeAbortController;
      
      // Forward client headers if provided, fallback to env vars
      const clientReferer = req.headers['http-referer'] || req.headers['referer'];
      const clientTitle = req.headers['x-title'];
      
      const remainingMs = CONFIG.TOTAL_REQUEST_TIMEOUT_MS - (Date.now() - requestStartTime);
      const axiosConfig = {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${currentKey}`,
          'HTTP-Referer': sanitizeHeaderValue(clientReferer || CONFIG.HTTP_REFERER),
          'X-Title': sanitizeHeaderValue(clientTitle || CONFIG.SITE_NAME),
          ...forwardedAttributionHeaders(req),
          'X-Request-ID': requestId
        },
        timeout: Math.max(100, Math.min(CONFIG.AXIOS_TIMEOUT, remainingMs)),
        signal: createAbortSignal(abortController, remainingMs)
      };

      if (isStreaming) {
        axiosConfig.responseType = 'stream';
      }

      // Exact OpenRouter IDs pass through; advertised/normalized names are resolved (variant-aware)
      openAIBody.model = toOpenRouterModelId(openAIBody.model);
      
      const response = await axiosInstance.post(
        'https://openrouter.ai/api/v1/chat/completions',
        openAIBody,
        axiosConfig
      );

      if (isStreaming) {
        // Track whether any bytes reached the client on this attempt, so a
        // later error knows whether a retry/failover is still safe (mirrors
        // the same pattern used in the /v1/chat/completions handler).
        const originalWrite = res.write;
        try {
          res.write = function(chunk) {
            if (chunk && chunk.length > 0) streamDataSent = true;
            return originalWrite.apply(this, arguments);
          };
          await keyManager.markKeySuccess();
          await handleAnthropicStreamingResponse(response, req, res, abortController, {
            requestId, model: currentFailoverModel
          });
          return;
        } finally {
          res.write = originalWrite;
        }
      }

      // Check for error in response body
      const responseData = response.data;
      if (responseData?.error?.message) {
        const errorMessage = responseData.error.message;
        
        // Use centralized rate limit detection (handles NVIDIA, Xiaomi MiMo, and generic)
        const isRateLimit = KeyManager.isRateLimitError({
          response: {
            data: responseData,
            status: 200,
            headers: response.headers
          }
        });
        
        if (isRateLimit) {
          logInfo('Rate limit detected in response', { 
            context: 'Anthropic Response', 
            errorMessage: errorMessage.substring(0, 200) 
          });
          const error = new Error('Rate limit in response');
          error.response = { data: responseData, status: 200, headers: response.headers };
          error.isRateLimit = true;
          throw error;
        }
        
        const statusCode = response.status || 400;
        if (failoverManager.shouldFailover({ response: { status: statusCode, data: responseData } })) {
          innerLoopError = new Error('OpenRouter error in response body');
          innerLoopError.response = { status: statusCode, data: responseData };
          innerLoopStatusCode = statusCode;
          break;
        }
        return res.status(statusCode).json(normalizeAnthropicError(normalizeErrorResponse(responseData, statusCode), statusCode));
      }
      
      await keyManager.markKeySuccess();
      
      // Non-streaming: parse and transform response
      const anthropicResponse = {
        id: responseData.id?.replace('chatcmpl-', 'msg_') || `msg_${Date.now()}`,
        type: 'message',
        role: 'assistant',
        content: [],
        model: responseData.model,
        stop_reason: mapFinishReason(responseData.choices?.[0]?.finish_reason),
        stop_sequence: null,
        usage: {
          input_tokens: responseData.usage?.prompt_tokens || 0,
          output_tokens: responseData.usage?.completion_tokens || 0
        }
      };
      
      // Handle content
      const choice = responseData.choices?.[0];
      if (choice?.message?.content) {
        anthropicResponse.content.push({
          type: 'text',
          text: choice.message.content
        });
      }
      
      // Handle tool calls
      if (choice?.message?.tool_calls) {
        anthropicResponse.stop_reason = 'tool_use';
        choice.message.tool_calls.forEach(tc => {
          let parsedInput = {};
          try {
            parsedInput = JSON.parse(tc.function.arguments);
          } catch {
            // Pass raw string if JSON parsing fails — don't retry on parse errors
            parsedInput = { _raw: tc.function.arguments };
          }
          anthropicResponse.content.push({
            type: 'tool_use',
            id: tc.id,
            name: tc.function.name,
            input: parsedInput
          });
        });
      }
      
      return res.json(anthropicResponse);
      
    } catch (error) {
      const keyRateLimit = await keyManager.markKeyError(error);
      const classified = classifyError(error);
      const isRateLimit = isRateLimitError({ keyRateLimit, classified });
      const retryDelayMs = keyManager.calculateRetryDelay ? keyManager.calculateRetryDelay(retryCount) : CONFIG.RETRY_DELAY_MS;
      const errorMessage = classified.errorMessage;
      const shouldRetryForNetwork = classified.shouldRetryForNetwork;

      // If the client disconnected, do NOT retry — downstream is gone
      if (isClientDisconnect(activeAbortController, classified)) {
        return;
      }

      // Once any bytes have reached the client on this stream, a retry or
      // failover would corrupt/duplicate output — terminate with an
      // Anthropic-format error event instead of retrying silently.
      if (isStreaming && streamDataSent) {
        if (!res.writableEnded) {
          res.write(normalizeAnthropicStreamError(error?.response?.data || error, error.response?.status || 500));
          res.end();
        }
        return;
      }

      // Don't retry if response has already started (streaming data sent)
      if (!res.headersSent && (isRateLimit || error.code === 'NO_AVAILABLE_KEYS' || error.response?.status >= 500 || shouldRetryForNetwork) && retryCount < maxRetries - 1) {
        // If we've already spent more time than the total budget, don't retry
        const elapsedBeforeRetry = Date.now() - requestStartTime;
        if (elapsedBeforeRetry >= CONFIG.TOTAL_REQUEST_TIMEOUT_MS) {
          logError(new Error('Total request timeout exceeded before retry'), {
            context: 'Anthropic messages',
            elapsedMs: elapsedBeforeRetry,
            timeoutMs: CONFIG.TOTAL_REQUEST_TIMEOUT_MS,
            retryCount
          });
          return res.status(504).json(normalizeErrorResponse(
            'Request timeout: total processing time exceeded limit',
            504
          ));
        }
        retryCount++;
        
        // Determine wait time using shared helper (caps at remaining budget)
        const remainingMs = CONFIG.TOTAL_REQUEST_TIMEOUT_MS - (Date.now() - requestStartTime);
        const { waitMs, waitReason, shouldAbort } = calculateRetryDelay({
          error, isRateLimit, retryCount, keyManager, remainingMs, retryDelayMs
        });
        
        if (shouldAbort) {
          return res.status(504).json(normalizeErrorResponse(
            'Request timeout: total processing time exceeded limit',
            504
          ));
        }
        
        if (isRateLimit || error.code === 'NO_AVAILABLE_KEYS' || shouldRetryForNetwork) {
          logRetry('anthropic', { retryCount, maxRetries, waitMs, waitReason, errorCode: error.code, errorMessage });
          await new Promise(resolve => setTimeout(resolve, waitMs));
        }
        continue;
      }
      
      logError(error, { 
        context: 'Anthropic messages',
        retryCount,
        statusCode: error.response?.status,
        responseData: error.response?.data
      });
      
      // Store error for outer loop (failover) consideration
      innerLoopError = error;
      innerLoopStatusCode = error.response?.status || 500;
      break;
    }
  }
  // End of inner retry loop

  // Inner loop finished without success — check if we can failover
  // Don't failover if response has already started (streaming data sent)
  if (innerLoopError && !res.headersSent && failoverManager.shouldFailover(innerLoopError) && modelIdx < failoverChain.length - 1) {
    continue;
  }

  // No more failover models, or error is not failoverable — return error to client
  if (innerLoopError) {
    const errorForResponse = innerLoopError?.response?.data || innerLoopError;
    if (!res.headersSent) {
      return res.status(innerLoopStatusCode).json(normalizeAnthropicError(normalizeErrorResponse(errorForResponse, innerLoopStatusCode), innerLoopStatusCode));
    }
    return;
  }
  }
  // End of outer failover loop — all models exhausted
  if (!res.headersSent) {
    return res.status(503).json(normalizeAnthropicError(
      normalizeErrorResponse('All models in failover chain exhausted', 503),
      503
    ));
  }
});

// Error handling middleware

app.use((err, req, res, next) => {
  logError(err, {
    context: 'Global error handler',
    url: req.url,
    method: req.method
  });

  if (res.headersSent) {
    return next(err);
  }

  // Express/body-parser errors carry their own status; honor it instead of
  // masking everything (e.g. a 413 body-too-large or 400 malformed JSON from
  // an agent) as a generic 500 "Internal server error".
  const statusCode = err?.status || err?.statusCode || 500;
  const message = statusCode >= 500
    ? 'Internal server error'
    : String(err?.message || 'Invalid request');

  res.status(statusCode).json({
    error: {
      message,
      type: statusCode >= 500 ? 'internal_error' : 'invalid_request_error'
    }
  });
});

const PORT = CONFIG.PORT;
const server = app.listen(PORT, () => {
  console.log(`OpenRouter Proxy Server running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
  
  // Force close after 10 seconds
  setTimeout(() => {
    console.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully...');
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
  
  setTimeout(() => {
    console.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
});