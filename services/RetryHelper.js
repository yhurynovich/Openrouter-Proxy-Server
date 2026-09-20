import { logInfo, logError } from './logger.js';
import { KeyManager } from './KeyManager.js';

/**
 * RetryHelper: shared utilities for error classification, retry-delay
 * calculation, and timeout signal management across all proxy endpoints.
 *
 * Eliminates ~300 lines of duplicated retry logic between the chat-completions,
 * Anthropic-messages, and models endpoints.
 */

const MAX_TIMEOUT_MS = 2147483647; // 2^31 - 1 — setTimeout/clamp ceiling

// Codes that represent transient network failures warranting a retry.
const NETWORK_ERROR_CODES = new Set([
  'ECONNRESET',
  'ETIMEDOUT',
  'ECONNABORTED',
  'ENOTFOUND',
  'ENETUNREACH',
  'EAI_AGAIN',
  'EHOSTUNREACH',
  'EPIPE',
  'ECONNREFUSED',
  'DNS_LOOKUP_TIMEOUT',
]);

// Idle-timeout message fragments used by some upstreams.
const IDLE_TIMEOUT_FRAGMENTS = [
  'idle timeout',
  'upstream idle timeout',
  'connection timeout',
  'connection closed',
  'socket hang up',
];

const GENERIC_TIMEOUT_RE = /\btimed?\s*out\b/i;
const AXIOS_TIMEOUT_CODE = 'ECONNABORTED';

/**
 * Safely stringify a value for logging without throwing.
 */
function safeStringifyForLog(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/**
 * Create an abort signal that fires on *either* client disconnect *or*
 * timeout expiry — whichever comes first.
 *
 * Hard in-flight cancellation guarantee: no single axios request can
 * overshoot TOTAL_REQUEST_TIMEOUT_MS.  Merges the request-scoped
 * AbortController with an AbortSignal.timeout() using AbortSignal.any()
 * when available; falls back to manual addEventListener + setTimeout merging
 * for Node 17.3–18.16 (which has AbortSignal.timeout but not AbortSignal.any).
 *
 * @param {AbortController} abortController - request-scoped controller for client disconnect
 * @param {number} remainingMs - ms left in the total request budget
 * @returns {AbortSignal} combined signal
 */
function createAbortSignal(abortController, remainingMs) {
  // Budget already exhausted — return an already-aborted signal so axios
  // never issues an unbounded upstream request.
  if (remainingMs <= 0) {
    const c = new AbortController();
    c.abort(new Error('Budget already exhausted'));
    return c.signal;
  }

  const budgetMs = Math.max(1, Math.min(remainingMs, MAX_TIMEOUT_MS));

  // Modern path: both available (Node >= 18.17)
  if (typeof AbortSignal.timeout === 'function' && typeof AbortSignal.any === 'function') {
    const timeoutSignal = AbortSignal.timeout(budgetMs);
    return AbortSignal.any([abortController.signal, timeoutSignal]);
  }

  // Fallback: manual merge via addEventListener + setTimeout (Node < 18.17).
  // { once: true } auto-removes listeners; timer.unref() lets process exit.
  const controller = new AbortController();
  let timeoutSignal = null;

  const onAbort = () => {
    const reason = abortController.signal.aborted
      ? abortController.signal.reason || new Error('Client disconnected')
      : new Error('Request timeout');
    controller.abort(reason);
  };

  abortController.signal.addEventListener('abort', onAbort, { once: true });

  if (typeof AbortSignal.timeout === 'function') {
    timeoutSignal = AbortSignal.timeout(budgetMs);
    timeoutSignal.addEventListener('abort', onAbort, { once: true });
  } else {
    const timer = setTimeout(() => controller.abort(new Error('Request timeout')), budgetMs);
    if (typeof timer.unref === 'function') {
      timer.unref();
    }
  }

  return controller.signal;
}

/**
 * Classify an axios/runtime error into structured fields used by
 * every endpoint's retry logic.
 */
function classifyError(error) {
  const errorData = error?.response?.data;
  const rawErrorMessage =
    errorData?.error?.message ||
    errorData?.message ||
    (typeof errorData === 'string' ? errorData : null);
  const errorMessage = safeStringifyForLog(rawErrorMessage);

  const lowerMessage = errorMessage.toLowerCase();

  const isRateLimitFromError = error?.isRateLimit === true;
  const isNetworkError = !!(error?.code && NETWORK_ERROR_CODES.has(error.code));
  const isTimeoutAbort = error?.name === 'AbortError' || error?.code === 'ERR_CANCELED' || error?.code === AXIOS_TIMEOUT_CODE;
  const isIdleTimeout =
    isTimeoutAbort ||
    IDLE_TIMEOUT_FRAGMENTS.some((frag) => lowerMessage.includes(frag)) ||
    GENERIC_TIMEOUT_RE.test(errorMessage);

  return {
    errorData,
    errorMessage,
    isRateLimitFromError,
    isNetworkError,
    isIdleTimeout,
    isTimeoutAbort,
    shouldRetryForNetwork: isNetworkError || isIdleTimeout,
    statusCode: error?.response?.status,
    headers: error?.response?.headers,
  };
}

/**
 * Determine whether the error is a rate-limit condition, using every
 * detection channel available: markKeyError result, KeyManager.isRateLimitError
 * (static), and the isRateLimit flag set in the response-body path.
 *
 * @param {object} params
 * @param {boolean} params.keyRateLimit   result of keyManager.markKeyError()
 * @param {object}  params.classified     output of classifyError()
 * @returns {boolean}
 */
function isRateLimitError({ keyRateLimit, classified }) {
  if (keyRateLimit) return true;

  const isRateLimitFromResponse = KeyManager.isRateLimitError({
    response: {
      data: classified.errorData,
      status: classified.statusCode,
      headers: classified.headers,
    },
  });

  return isRateLimitFromResponse || classified.isRateLimitFromError;
}

/**
 * Calculate the retry wait time in ms, taking into account the total
 * request timeout budget so we never overshoot.
 *
 * Collects candidate wait times from multiple sources (rate-limit reset
 * headers, NO_AVAILABLE_KEYS minWaitMs) and picks the minimum viable one.
 * Always clamps the final result to the remaining budget.
 *
 * @param {object} params
 * @param {Error}   params.error           the original error (may carry minWaitMs / headers)
 * @param {boolean} params.isRateLimit
 * @param {number}  params.remainingMs     ms left in total budget
 * @param {number}  params.retryDelayMs    base exponential backoff delay
 * @returns {{ waitMs: number, waitReason: string, shouldAbort: boolean }}
 */
function calculateRetryDelay({ error, isRateLimit, keyManager, remainingMs, retryDelayMs }) {
  // Budget already exhausted — abort immediately, no sleep
  if (remainingMs <= 0) {
    return { waitMs: 0, waitReason: 'budget exhausted', shouldAbort: true };
  }

  // If even the base backoff exceeds the budget, abort
  if (retryDelayMs > remainingMs) {
    return { waitMs: 0, waitReason: 'retry delay exceeds budget', shouldAbort: true };
  }

  let waitMs = retryDelayMs;
  let waitReason = 'exponential backoff';

  // Collect candidate wait times from all sources
  const candidates = [];

  // 1. Upstream rate-limit reset header (when it fits within budget)
  if (isRateLimit && error?.response?.headers) {
    try {
      const resetDate = keyManager.parseRateLimitReset(error.response.headers);
      const resetWaitMs = resetDate.getTime() - Date.now();
      if (resetWaitMs > 0 && resetWaitMs <= remainingMs) {
        candidates.push({ ms: resetWaitMs, reason: 'rate limit reset time' });
      }
    } catch {
      // parseRateLimitReset can throw on unexpected header formats; fall back to exponential backoff
    }
  }

  // 2. NO_AVAILABLE_KEYS carries its own authoritative minWaitMs
  if (error?.code === 'NO_AVAILABLE_KEYS' && error.minWaitMs != null) {
    if (error.minWaitMs > remainingMs) {
      return { waitMs: 0, waitReason: 'key reset exceeds budget', shouldAbort: true };
    }
    candidates.push({ ms: error.minWaitMs, reason: 'key reset time' });
  }

  // Pick the minimum candidate that is positive and fits within budget
  if (candidates.length > 0) {
    const valid = candidates.filter((c) => c.ms > 0 && c.ms <= remainingMs);
    if (valid.length > 0) {
      valid.sort((a, b) => a.ms - b.ms);
      waitMs = Math.max(retryDelayMs, valid[0].ms);
      waitReason = valid[0].reason;
    }
  }

  // Clamp to remaining budget to never overshoot TOTAL_REQUEST_TIMEOUT_MS
  if (waitMs > remainingMs) {
    return { waitMs: 0, waitReason: 'clamped to budget', shouldAbort: true };
  }

  return { waitMs, waitReason, shouldAbort: false };
}

/**
 * Check if the abort signal was triggered by a client disconnect (as
 * opposed to a timeout).  When true, the caller must NOT retry — the
 * downstream client is gone and any retry would waste keys/quota.
 *
 * @param {AbortController} abortController - the request-scoped controller
 * @param {object} classified               output of classifyError()
 * @returns {boolean}
 */
function isClientDisconnect(abortController, classified) {
  // When client disconnects, abortController.signal.aborted is true.
  // When timeout fires, abortController.signal.aborted stays false
  // (only the timeout signal fired, not the client's signal).
  return abortController?.signal.aborted === true;
}

/**
 * Log a retry event with a rich context object.
 *
 * @param {string} endpointLabel  e.g. 'chat completions', 'models', 'anthropic'
 * @param {object} ctx            structured fields
 */
function logRetry(endpointLabel, ctx) {
  const { retryCount, maxRetries, waitMs, waitReason, errorCode, errorMessage } = ctx;
  const safeMsg = errorMessage != null
    ? safeStringifyForLog(errorMessage).slice(0, 200)
    : '';
  const msg = `[Retry] Error on ${endpointLabel} (${errorCode || safeMsg || 'unknown'}), waiting ${waitMs}ms before retry (attempt ${retryCount}/${maxRetries}, ${waitReason})...`;
  logInfo(msg, {
    context: `${endpointLabel} Retry`,
    retryCount,
    maxRetries,
    delayMs: waitMs,
    waitReason,
    errorCode,
    errorMessage: safeMsg,
  });
}

/**
 * Check if total request timeout has been exceeded; if so, sends a 504
 * response and returns true.  Returns false if still within budget.
 */
function checkTotalTimeout(res, requestStartTime, totalTimeoutMs, retryCount, context) {
  const elapsedMs = Date.now() - requestStartTime;
  if (elapsedMs >= totalTimeoutMs) {
    logError('Total request timeout exceeded', {
      context,
      elapsedMs,
      timeoutMs: totalTimeoutMs,
      retryCount,
    });
    if (!res.headersSent) {
      res.status(504).json({
        error: {
          message: 'Request timeout: total processing time exceeded limit',
          type: 'timeout',
        },
      });
    }
    return true;
  }
  return false;
}

export {
  createAbortSignal,
  classifyError,
  isRateLimitError,
  calculateRetryDelay,
  isClientDisconnect,
  logRetry,
  checkTotalTimeout,
};
