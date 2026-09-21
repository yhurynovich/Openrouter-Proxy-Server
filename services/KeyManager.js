import ApiKey from '../models/ApiKey.js';
import { logKeyEvent, logError } from './logger.js';

const KEY_MANAGER_CONFIG = {
  MAX_ROTATION_DEPTH: parseInt(process.env.KEY_MAX_ROTATION_DEPTH || '3', 10),
  MAX_FAILURE_COUNT: parseInt(process.env.KEY_MAX_FAILURE_COUNT || '5', 10),
  REACTIVATION_FAILURE_REDUCTION: parseInt(process.env.KEY_REACTIVATION_FAILURE_REDUCTION || '2', 10),
  ROTATE_KEY_TIMEOUT_MS: parseInt(process.env.KEY_ROTATE_TIMEOUT_MS || '30000', 10),
  // Rate limit header parsing thresholds
  UNIX_TIMESTAMP_THRESHOLD: 1e9,        // Unix timestamp in seconds (before year 2001)
  MILLISECOND_THRESHOLD: 1e12,          // Milliseconds since epoch (year ~2001+)
  PADDED_SECOND_THRESHOLD: 1e13,        // Seconds with 3 padded zeros (year ~2286+)
  DEFAULT_RATE_LIMIT_WINDOW_MS: 60000,  // Default 1 minute fallback
  // Retry configuration
  BASE_RETRY_DELAY_MS: parseInt(process.env.KEY_BASE_RETRY_DELAY_MS || '1000', 10),
  MAX_RETRY_DELAY_MS: parseInt(process.env.KEY_MAX_RETRY_DELAY_MS || '30000', 10),
  RETRY_JITTER_FACTOR: 0.3
};

/**
 * Validate OpenRouter API key format
 * @param {string} key - API key to validate
 * @returns {boolean} true if valid format
 */
function validateApiKeyFormat(key) {
  if (!key || typeof key !== 'string') {
    return false;
  }
  // OpenRouter keys typically start with 'sk-or-' and are at least 20 chars
  const trimmed = key.trim();
  if (trimmed.length < 20) {
    return false;
  }
  // Check for common OpenRouter key prefix
  if (!trimmed.startsWith('sk-or-')) {
    // Allow other formats but warn
    logError(new Error('API key format warning'), { 
      action: 'validateApiKeyFormat', 
      message: 'API key does not have expected sk-or- prefix',
      keyPreview: trimmed.substring(0, 10) + '...'
    });
  }
  return true;
}

class KeyManager {
  #rotationPromise = null;

  constructor() {
    this.currentKey = null;
  }

  async initialize() {
    if (!this.currentKey) {
      await this.rotateKey();
    }
  }

  async rotateKey(depth = 0) {
    // Prevent infinite recursion
    if (depth > KEY_MANAGER_CONFIG.MAX_ROTATION_DEPTH) {
      const error = new Error('Max key rotation depth exceeded - no available keys');
      logError(error);
      throw error;
    }

    // Return existing rotation promise if one is in progress (mutex pattern)
    if (this.#rotationPromise) {
      return this.#rotationPromise;
    }

    const p = this.#doRotateKey(depth);
    this.#rotationPromise = p;

    try {
      // Overall timeout — prevent rotateKey from hanging indefinitely if
      // upstream key store or DNS is stuck. Callers awaiting the rotation
      // promise won't block forever.
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => {
          reject(new Error(`rotateKey timed out after ${KEY_MANAGER_CONFIG.ROTATE_KEY_TIMEOUT_MS}ms`));
        }, KEY_MANAGER_CONFIG.ROTATE_KEY_TIMEOUT_MS);
      });
      return await Promise.race([p, timeoutPromise]);
    } finally {
      // Only clear if still pointing at us — a concurrent caller may have
      // installed a newer rotation promise while we awaited.
      if (this.#rotationPromise === p) {
        this.#rotationPromise = null;
      }
    }
  }

  async #doRotateKey(depth = 0) {
    
    try {
      // Get a working key that's not in cooldown
      // Get all keys and filter/sort manually
      const keys = await ApiKey.findAll({
        isActive: true,
        $or: [
          { rateLimitResetAt: null },
          { rateLimitResetAt: { $lte: new Date() } }
        ]
      });

      // Sort by lastUsed ascending (oldest first)
      const key = keys.sort((a, b) => {
        if (!a.lastUsed) return -1;
        if (!b.lastUsed) return 1;
        return new Date(a.lastUsed) - new Date(b.lastUsed);
      })[0];

      if (!key) {
        // No keys available - attempt to reactivate all keys first
        const reactivated = await this.reactivateAllKeys();
        if (reactivated) {
          // Recurse directly into #doRotateKey (not rotateKey) so the
          // rotation mutex stays held — prevents concurrent rotations from
          // racing on key selection.
          return await this.#doRotateKey(depth + 1);
        }
        
        // No keys available even after reactivation - calculate estimated wait time
        const allKeys = await ApiKey.findAll({ isActive: true });
        const now = new Date();
        let minWaitMs = null;
        
        for (const k of allKeys) {
          if (k.rateLimitResetAt && k.rateLimitResetAt > now) {
            const waitMs = k.rateLimitResetAt.getTime() - now.getTime();
            if (minWaitMs === null || waitMs < minWaitMs) {
              minWaitMs = waitMs;
            }
          }
        }
        
        let errorMessage = 'No available API keys';
        if (minWaitMs !== null) {
          const waitSeconds = Math.ceil(minWaitMs / 1000);
          const waitMinutes = Math.ceil(waitSeconds / 60);
          if (waitSeconds < 60) {
            errorMessage += ` - try again in ~${waitSeconds} seconds`;
          } else {
            errorMessage += ` - try again in ~${waitMinutes} minute(s)`;
          }
        }
        
        const error = new Error(errorMessage);
        // Attach wait time for caller to use
        error.minWaitMs = minWaitMs;
        error.code = 'NO_AVAILABLE_KEYS';
        logError(error);
        throw error;
      }

      this.currentKey = key;
      
      // Log key rotation
      logKeyEvent('Key Rotation', {
        keyId: key._id,
        lastUsed: key.lastUsed,
        failureCount: key.failureCount
      });

      return key.key;
    } catch (error) {
      logError(error, { action: 'rotateKey' });
      throw error;
    }
  }

  async markKeySuccess() {
    if (this.currentKey) {
      try {
        this.currentKey.lastUsed = new Date();
        await this.currentKey.save();
        logKeyEvent('Key Success', {
          keyId: this.currentKey._id,
          lastUsed: this.currentKey.lastUsed
        });
      } catch (error) {
        // Do not rethrow: the upstream request already succeeded; a save
        // failure only means lastUsed is stale, not that the key is bad.
        // Log prominently so the operator knows key rotation state is stale.
        logError(error, {
          action: 'markKeySuccess',
          keyId: this.currentKey?._id,
          message: 'Failed to persist key success state — lastUsed may be stale',
        });
      }
    }
  }

  /**
   * Check if an error response contains NVIDIA rate limit error
   * Error format: "Upstream error from Nvidia: ResourceExhausted: Worker local total request limit reached (32/32)"
   * Also handles "Upstream error from Nvidia: Service temporarily overloaded"
   */
  static isNvidiaRateLimitError(error) {
    if (!error.response?.data) return false;
    
    const data = error.response.data;
    // Check both OpenAI error format and raw text - safely stringify
    const safeStringify = (obj) => {
      try {
        return JSON.stringify(obj);
      } catch {
        return String(obj);
      }
    };
    const errorMessage = data.error?.message || 
                         data.message || 
                         safeStringify(data);
    
    if (typeof errorMessage !== 'string') return false;
    
    const lowerMessage = errorMessage.toLowerCase();
    
    return lowerMessage.includes('upstream error from nvidia') && 
           (lowerMessage.includes('resourceexhausted') || 
            lowerMessage.includes('rate limit') ||
            lowerMessage.includes('limit reached') ||
            lowerMessage.includes('service temporarily overloaded') ||
            lowerMessage.includes('overloaded') ||
            lowerMessage.includes('temporarily unavailable') ||
            lowerMessage.includes('try again') ||
            lowerMessage.includes('capacity'));
  }

  /**
   * Check if an error response contains any rate limit error
   * Handles NVIDIA, Xiaomi MiMo, and generic rate limit patterns
   * Also checks response body for rate limit indicators regardless of HTTP status code
   */
  static isRateLimitError(error) {
    // Check HTTP status code first - 429 is definitive
    if (error.response?.status === 429) {
      return true;
    }
    
    if (!error.response?.data) return false;
    
    const data = error.response.data;
    const safeStringify = (obj) => {
      try {
        return JSON.stringify(obj);
      } catch {
        return String(obj);
      }
    };
    const errorMessage = data.error?.message || 
                         data.message || 
                         safeStringify(data);
    
    if (typeof errorMessage !== 'string') return false;
    
    const lowerMessage = errorMessage.toLowerCase();
    
    // NVIDIA rate limits
    if (lowerMessage.includes('upstream error from nvidia') && 
        (lowerMessage.includes('resourceexhausted') || 
         lowerMessage.includes('rate limit') ||
         lowerMessage.includes('limit reached') ||
         lowerMessage.includes('service temporarily overloaded') ||
         lowerMessage.includes('overloaded'))) {
      return true;
    }
    
    // Xiaomi MiMo studio rate limits
    if (lowerMessage.includes('xiaomi') || lowerMessage.includes('mimo')) {
      if (lowerMessage.includes('rate limit') || 
          lowerMessage.includes('quota exceeded') ||
          lowerMessage.includes('too many requests') ||
          lowerMessage.includes('rate limited') ||
          lowerMessage.includes('throttl') ||
          lowerMessage.includes('idle timeout') ||
          lowerMessage.includes('upstream idle timeout') ||
          lowerMessage.includes('capacity') ||
          lowerMessage.includes('busy') ||
          lowerMessage.includes('overload')) {
        return true;
      }
    }
    
    // Generic rate limit patterns (OpenRouter, OpenAI, Anthropic, etc.)
    if (lowerMessage.includes('rate limit') || 
        lowerMessage.includes('quota exceeded') ||
        lowerMessage.includes('too many requests') ||
        lowerMessage.includes('rate limited') ||
        lowerMessage.includes('throttl') ||
        lowerMessage.includes('429') ||
        (lowerMessage.includes('limit') && lowerMessage.includes('exceeded'))) {
      return true;
    }
    
    // Idle timeout patterns
    if (lowerMessage.includes('idle timeout') || 
        lowerMessage.includes('connection timeout') ||
        lowerMessage.includes('upstream idle timeout') ||
        lowerMessage.includes('connection closed') ||
        lowerMessage.includes('socket hang up') ||
        lowerMessage.includes('econnreset') ||
        lowerMessage.includes('etimedout') ||
        lowerMessage.includes('econnaborted')) {
      return true;
    }
    
    // Provider-specific transient error patterns that may appear with various status codes
    // These patterns in the response body suggest a temporary issue worth retrying
    const transientPatterns = [
      'temporarily unavailable',
      'service unavailable',
      'try again later',
      'try again in',
      'please retry',
      'capacity exceeded',
      'model overloaded',
      'provider overloaded',
      'upstream error',
      'gateway timeout',
      'upstream timeout',
      'rate limit',
      'quota',
      'throttl',
      'too many requests',
    ];
    
    for (const pattern of transientPatterns) {
      if (lowerMessage.includes(pattern)) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Parse rate limit reset header from OpenRouter response
   * Handles multiple formats: seconds with padded zeros, milliseconds, seconds, or relative seconds
   * Also handles Xiaomi MiMo specific headers
   * @param {Object} headers - Response headers
   * @returns {Date} Reset date
   */
  parseRateLimitReset(headers) {
    // Handle null/undefined headers (e.g., when originalError.response?.headers is undefined)
    if (!headers) {
      headers = {};
    }
    
    // Check multiple possible header names (case-insensitive)
    const headerNames = [
      'ratelimit-reset',
      'x-ratelimit-reset',
      'retry-after',
      'x-rate-limit-reset',
      'x-ratelimit-reset-after',
      'rate-limit-reset'
    ];
    
    let resetTime = null;
    for (const name of headerNames) {
      // Headers in axios are lowercased
      const lowerName = name.toLowerCase();
      if (headers && headers[lowerName]) {
        resetTime = headers[lowerName];
        break;
      }
    }
    
    if (!resetTime) {
      return new Date(Date.now() + KEY_MANAGER_CONFIG.DEFAULT_RATE_LIMIT_WINDOW_MS);
    }
    
    const resetNum = parseInt(resetTime, 10);
    if (isNaN(resetNum)) {
      // Handle HTTP-date format (e.g., "Wed, 21 Oct 2015 07:28:00 GMT")
      const parsedDate = new Date(resetTime);
      if (!isNaN(parsedDate.getTime())) {
        return parsedDate;
      }
      return new Date(Date.now() + KEY_MANAGER_CONFIG.DEFAULT_RATE_LIMIT_WINDOW_MS);
    }
    
    // OpenRouter uses seconds with 3 padded zeros (e.g., 1785369600000 = 1785369600 seconds)
    // Values > 1e12 could be either milliseconds since epoch OR seconds with padded zeros
    // Both give similar years, but we need to handle correctly
    if (resetNum > KEY_MANAGER_CONFIG.MILLISECOND_THRESHOLD) {
      // If value > 1e13, it's definitely seconds with padded zeros (year > 2286)
      // Otherwise, treat as milliseconds since epoch (more common)
      if (resetNum > KEY_MANAGER_CONFIG.PADDED_SECOND_THRESHOLD) {
        // Seconds with 3 padded zeros - divide by 1000 to get seconds, then multiply by 1000 for milliseconds
        return new Date(Math.floor(resetNum / 1000) * 1000);
      }
      // Milliseconds since epoch
      return new Date(resetNum);
    }
    // Seconds since epoch (Unix timestamp)
    if (resetNum > KEY_MANAGER_CONFIG.UNIX_TIMESTAMP_THRESHOLD) {
      return new Date(resetNum * 1000);
    }
    // Relative seconds from now (or retry-after header in seconds)
    return new Date(Date.now() + resetNum * 1000);
  }

  /**
   * Calculate exponential backoff delay with jitter
   * @param {number} retryCount - Current retry attempt (0-indexed)
   * @returns {number} Delay in milliseconds
   */
  calculateRetryDelay(retryCount) {
    const baseDelay = KEY_MANAGER_CONFIG.BASE_RETRY_DELAY_MS;
    const maxDelay = KEY_MANAGER_CONFIG.MAX_RETRY_DELAY_MS;
    const jitterFactor = KEY_MANAGER_CONFIG.RETRY_JITTER_FACTOR;
    
    // Exponential backoff: baseDelay * 2^retryCount
    const exponentialDelay = baseDelay * Math.pow(2, retryCount);
    const cappedDelay = Math.min(exponentialDelay, maxDelay);
    
    // Add jitter: ±jitterFactor * cappedDelay
    const jitter = cappedDelay * jitterFactor * (Math.random() * 2 - 1);
    
    return Math.floor(Math.max(baseDelay, cappedDelay + jitter));
  }

  async markKeyError(originalError) {
    if (!this.currentKey) return;

    try {
      // Check if it's a rate limit error (HTTP 429)
      const isHttpRateLimit = originalError.response && originalError.response.status === 429;

      // Check for any rate limit error (NVIDIA, Xiaomi MiMo, generic, idle timeout)
      const isRateLimitError = KeyManager.isRateLimitError(originalError);

      const isRateLimit = isHttpRateLimit || isRateLimitError;

      if (isRateLimit) {
        // OpenRouter uses 'ratelimit-reset' header (lowercase, no x- prefix)
        const resetDate = this.parseRateLimitReset(originalError.response?.headers);
        logKeyEvent('Rate Limit Reset Parsed', {
          resetDateUtc: resetDate.toISOString(),
          resetDateLocal: resetDate.toString()
        });
        this.currentKey.rateLimitResetAt = resetDate;

        logKeyEvent('Rate Limit Hit', {
          keyId: this.currentKey._id,
          resetTime: this.currentKey.rateLimitResetAt,
          isNvidia: isRateLimitError && originalError.message?.includes?.('Nvidia') || false
        });

        // Persist rate-limit state. If save fails, keep currentKey (with in-memory
        // rateLimitResetAt) to prevent immediate re-selection and retry loops.
        try {
          await this.currentKey.save();
          // Successfully persisted - safe to clear currentKey to force rotation
          this.currentKey = null;
        } catch (saveError) {
          logError(saveError, {
            action: 'markKeyError save failed',
            keyId: this.currentKey._id,
            originalErrorMessage: originalError?.message,
            originalStatusCode: originalError?.response?.status,
          });
          // Save failed - keep currentKey with in-memory rateLimitResetAt to
          // prevent immediate re-selection. The key won't be chosen again until
          // its rateLimitResetAt expires (based on in-memory value).
        }
        return true; // Indicate it was a rate limit error
      }

      this.currentKey.failureCount += 1;

      // If too many failures, deactivate the key
      if (this.currentKey.failureCount >= KEY_MANAGER_CONFIG.MAX_FAILURE_COUNT) {
        this.currentKey.isActive = false;
        logKeyEvent('Key Deactivated', {
          keyId: this.currentKey._id,
          reason: 'Too many failures',
          failureCount: this.currentKey.failureCount
        });
        // Clear current key to force rotation
        this.currentKey = null;
        // Auto-rotate to next available key
        try {
          await this.rotateKey();
        } catch (rotateError) {
          logError(rotateError, { action: 'autoRotateAfterDeactivation' });
        }
      } else {
        await this.currentKey.save();
      }

      return false; // Indicate it was not a rate limit error
    } catch (saveError) {
      // Log both the save/storage error and the original error context
      // so neither is lost. Do NOT rethrow — callers expect a boolean
      // return and rely on the original error (still in scope) for
      // retry/failover decisions in the request handler.
      logError(saveError, {
        action: 'markKeyError',
        keyId: this.currentKey?._id,
        originalErrorMessage: originalError?.message,
        originalStatusCode: originalError?.response?.status,
      });
      return false;
    }
  }

  async getKey() {
    try {
      // If we have a current key and it's not in cooldown, keep using it
      if (this.currentKey) {
        const now = new Date();
        if (!this.currentKey.rateLimitResetAt || this.currentKey.rateLimitResetAt <= now) {
          return this.currentKey.key;
        }
      }
      
      // Otherwise rotate to a new key
      return await this.rotateKey();
    } catch (error) {
      logError(error, { action: 'getKey' });
      throw error;
    }
  }

  async addKey(key) {
    try {
      // Validate API key format
      if (!validateApiKeyFormat(key)) {
        const error = new Error('Invalid API key format');
        logError(error, { action: 'addKey', keyPreview: key?.substring(0, 10) + '...' });
        throw error;
      }
      
      const existingKey = await ApiKey.findOne({ key });
      if (existingKey) {
        existingKey.isActive = true;
        existingKey.failureCount = 0;
        existingKey.rateLimitResetAt = null;
        await existingKey.save();

        logKeyEvent('Key Reactivated', {
          keyId: existingKey._id
        });

        return existingKey;
      }

      const newKey = await ApiKey.create({ key });
      logKeyEvent('New Key Added', {
        keyId: newKey._id
      });

      return newKey;
    } catch (error) {
      logError(error, { action: 'addKey' });
      throw error;
    }
  }

  /**
   * Reactivate all inactive keys and clear rate limit cooldowns
   * Called when no keys are available to give them a second chance
   * Bulk read-modify-write to avoid O(N²) I/O stalls
   * @returns {boolean} true if any keys were reactivated, false otherwise
   */
  async reactivateAllKeys() {
    try {
      // Read all keys once
      const allKeys = await ApiKey.findAll({});
      let reactivated = 0;
      
      // Modify all keys that need reactivation in memory
      for (const key of allKeys) {
        if (!key.isActive || key.rateLimitResetAt) {
          key.isActive = true;
          // Graduated reset: reduce failure count but don't clear completely
          // This preserves some history of problematic keys
          key.failureCount = Math.max(0, key.failureCount - KEY_MANAGER_CONFIG.REACTIVATION_FAILURE_REDUCTION);
          key.rateLimitResetAt = null;
          reactivated++;
        }
      }
      
      // If any keys were reactivated, write them all back in one operation
      if (reactivated > 0) {
        await ApiKey.bulkWrite(allKeys);
        
        logKeyEvent('Bulk Key Reactivation', {
          reactivatedCount: reactivated,
          totalKeys: allKeys.length
        });
      }
      
      return reactivated > 0;
    } catch (error) {
      logError(error, { action: 'reactivateAllKeys' });
      // Re-throw so callers (#doRotateKey) can distinguish a genuine
      // storage failure from "no keys were reactivatable".
      throw error;
    }
  }
}

export { KeyManager };
export default new KeyManager();