import ApiKey from '../models/ApiKey.js';
import { logKeyEvent, logError } from './logger.js';

class KeyManager {
  constructor() {
    this.currentKey = null;
  }

  async initialize() {
    if (!this.currentKey) {
      await this.rotateKey();
    }
  }

  async rotateKey() {
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
          // Try to get a key again after reactivation
          return await this.rotateKey();
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
  isNvidiaRateLimitError(error) {
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

  async markKeyError(error) {
    if (!this.currentKey) return;

    try {
      // Check if it's a rate limit error (HTTP 429)
      const isHttpRateLimit = error.response?.status === 429;
      
      // Check for NVIDIA-specific rate limit in response body
      const isNvidiaRateLimit = this.isNvidiaRateLimitError(error);
      
      const isRateLimit = isHttpRateLimit || isNvidiaRateLimit;

      if (isRateLimit) {
        const resetTime = error.response.headers['x-ratelimit-reset'];
        this.currentKey.rateLimitResetAt = resetTime ? new Date(resetTime * 1000) : new Date(Date.now() + 60000);
        
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
      if (this.currentKey.failureCount >= 5) {
        this.currentKey.isActive = false;
        logKeyEvent('Key Deactivated', {
          keyId: this.currentKey._id,
          reason: 'Too many failures',
          failureCount: this.currentKey.failureCount
        });
        // Clear current key to force rotation
        this.currentKey = null;
      }

      await this.currentKey.save();
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
          key.failureCount = 0;
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