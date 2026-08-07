import ApiKey from '../models/ApiKey.js';
import { logKeyEvent, logError } from './logger.js';

const KEY_MANAGER_CONFIG = {
  MAX_ROTATION_DEPTH: parseInt(process.env.KEY_MAX_ROTATION_DEPTH || '2', 10),
  MAX_FAILURE_COUNT: parseInt(process.env.KEY_MAX_FAILURE_COUNT || '5', 10),
  REACTIVATION_FAILURE_REDUCTION: parseInt(process.env.KEY_REACTIVATION_FAILURE_REDUCTION || '2', 10),
  // Rate limit header parsing thresholds
  UNIX_TIMESTAMP_THRESHOLD: 1e9,        // Unix timestamp in seconds (before year 2001)
  MILLISECOND_THRESHOLD: 1e12,          // Milliseconds since epoch (year ~2001+)
  PADDED_SECOND_THRESHOLD: 1e13,        // Seconds with 3 padded zeros (year ~2286+)
  DEFAULT_RATE_LIMIT_WINDOW_MS: 60000   // Default 1 minute fallback
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

    this.#rotationPromise = this.#doRotateKey(depth);
    
    try {
      return await this.#rotationPromise;
    } finally {
      this.#rotationPromise = null;
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
          // Clear rotation promise before recursive call to avoid deadlock
          this.#rotationPromise = null;
          return await this.rotateKey(depth + 1);
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
        logError(error, { action: 'markKeySuccess' });
      }
    }
  }

  /**
   * Check if an error response contains NVIDIA rate limit error
   * Error format: "Upstream error from Nvidia: ResourceExhausted: Worker local total request limit reached (32/32)"
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
    
    return typeof errorMessage === 'string' && 
           errorMessage.includes('Upstream error from Nvidia') && 
           (errorMessage.includes('ResourceExhausted') || 
            errorMessage.includes('rate limit') ||
            errorMessage.includes('limit reached'));
  }

  /**
   * Parse rate limit reset header from OpenRouter response
   * Handles multiple formats: seconds with padded zeros, milliseconds, seconds, or relative seconds
   * @param {Object} headers - Response headers
   * @returns {Date} Reset date
   */
  parseRateLimitReset(headers) {
    const resetTime = headers?.['ratelimit-reset'] || headers?.['x-ratelimit-reset'] || headers?.['retry-after'];
    if (!resetTime) {
      return new Date(Date.now() + KEY_MANAGER_CONFIG.DEFAULT_RATE_LIMIT_WINDOW_MS);
    }
    
    const resetNum = parseInt(resetTime, 10);
    if (isNaN(resetNum)) {
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

  async markKeyError(error) {
    if (!this.currentKey) return;

    try {
      // Check if it's a rate limit error (HTTP 429)
      const isHttpRateLimit = error.response && error.response.status === 429;
      
      // Check for NVIDIA-specific rate limit in response body
      const isNvidiaRateLimit = KeyManager.isNvidiaRateLimitError(error);
      
      const isRateLimit = isHttpRateLimit || isNvidiaRateLimit;

      if (isRateLimit) {
        // OpenRouter uses 'ratelimit-reset' header (lowercase, no x- prefix)
        const resetDate = this.parseRateLimitReset(error.response?.headers);
        logKeyEvent('Rate Limit Reset Parsed', {
          resetDateUtc: resetDate.toISOString(),
          resetDateLocal: resetDate.toString()
        });
        this.currentKey.rateLimitResetAt = resetDate;
        
        logKeyEvent('Rate Limit Hit', {
          keyId: this.currentKey._id,
          resetTime: this.currentKey.rateLimitResetAt,
          isNvidia: isNvidiaRateLimit
        });

        await this.currentKey.save();
        // Clear current key to force rotation
        this.currentKey = null;
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
    } catch (error) {
      logError(error, { 
        action: 'markKeyError',
        keyId: this.currentKey?._id
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
   * @returns {boolean} true if any keys were reactivated, false otherwise
   */
  async reactivateAllKeys() {
    try {
      const allKeys = await ApiKey.findAll({});
      let reactivated = 0;
      
      for (const key of allKeys) {
        if (!key.isActive || key.rateLimitResetAt) {
          key.isActive = true;
          // Graduated reset: reduce failure count but don't clear completely
          // This preserves some history of problematic keys
          key.failureCount = Math.max(0, key.failureCount - KEY_MANAGER_CONFIG.REACTIVATION_FAILURE_REDUCTION);
          key.rateLimitResetAt = null;
          await key.save();
          reactivated++;
        }
      }
      
      if (reactivated > 0) {
        logKeyEvent('Bulk Key Reactivation', {
          reactivatedCount: reactivated,
          totalKeys: allKeys.length
        });
      }
      
      return reactivated > 0;
    } catch (error) {
      logError(error, { action: 'reactivateAllKeys' });
      return false;
    }
  }
}

export default new KeyManager();