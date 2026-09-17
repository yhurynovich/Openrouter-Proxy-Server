import { logKeyEvent, logInfo, logError } from './logger.js';

const FAILOVER_CONFIG = {
  MAX_MODEL_FAILOVERS: parseInt(process.env.MAX_MODEL_FAILOVERS || '0', 10),
};

function parseFailoverGroups() {
  const raw = process.env.MODEL_FAILOVER_GROUPS;
  if (!raw) {
    return [];
  }

  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      logError(new Error('MODEL_FAILOVER_GROUPS must be a JSON array of arrays'), {
        action: 'parseFailoverGroups',
      });
      return [];
    }

    const groups = parsed
      .filter((g) => Array.isArray(g) && g.length >= 2)
      .map((g) => g.map((m) => String(m).trim()));

    if (groups.length > 0) {
      logInfo('Failover groups loaded', {
        groupCount: groups.length,
        totalModels: groups.reduce((sum, g) => sum + g.length, 0),
      });
    }

    return groups;
  } catch (e) {
    logError(e, { action: 'parseFailoverGroups', raw });
    return [];
  }
}

function normalizeForMatch(modelId) {
  if (!modelId || typeof modelId !== 'string') return '';
  let n = modelId.split('/').pop();
  n = n.replace(/:free$/, '');
  n = n.replace(/:[\w-]+$/, '');
  return n.toLowerCase();
}

class FailoverManager {
  #groups = [];
  #lookup = new Map();

  initialize() {
    this.#groups = parseFailoverGroups();
    this.#lookup = new Map();

    for (const group of this.#groups) {
      for (const model of group) {
        this.#lookup.set(model, group);
        const normalized = normalizeForMatch(model);
        if (normalized) {
          this.#lookup.set(normalized, group);
        }
      }
    }

    if (this.#groups.length > 0) {
      logInfo('FailoverManager initialized', {
        groups: this.#groups.length,
      });
    }
  }

  isEnabled() {
    return this.#groups.length > 0;
  }

  getFailoverChain(model) {
    if (!model || !this.isEnabled()) {
      return null;
    }

    let group = this.#lookup.get(model);

    if (!group) {
      group = this.#lookup.get(normalizeForMatch(model));
    }

    if (!group) {
      return null;
    }

    if (group[0] === model) {
      return [...group];
    }

    const idx = group.indexOf(model);
    if (idx !== -1) {
      return [model, ...group.slice(0, idx), ...group.slice(idx + 1)];
    }

    return [...group];
  }

  getMaxFailoverSwitches() {
    return FAILOVER_CONFIG.MAX_MODEL_FAILOVERS === 0
      ? Infinity
      : FAILOVER_CONFIG.MAX_MODEL_FAILOVERS;
  }

  isModelOverloadedError(error) {
    const data = error?.response?.data;
    if (!data) return false;

    const safeStringify = (obj) => {
      try {
        return JSON.stringify(obj);
      } catch {
        return String(obj);
      }
    };

    const errorMessage =
      data.error?.message || data.message || safeStringify(data);

    if (typeof errorMessage !== 'string') return false;

    const lower = errorMessage.toLowerCase();

    return (
      lower.includes('overloaded') ||
      lower.includes('capacity') ||
      lower.includes('provider overloaded') ||
      lower.includes('no provider') ||
      lower.includes('temporarily unavailable')
    );
  }

  getFailoverErrorType(error) {
    if (!error) return 'unknown';

    if (error.code === 'NO_AVAILABLE_KEYS') {
      return 'keys_exhausted';
    }

    const status = error.response?.status;

    if (status === 400 || status === 401 || status === 403) {
      return 'non_retryable';
    }

    if (status === 429) {
      return 'rate_limit';
    }

    if (status >= 500) {
      return 'server_error';
    }

    if (
      error.code === 'ECONNRESET' ||
      error.code === 'ETIMEDOUT' ||
      error.code === 'ECONNABORTED' ||
      error.code === 'ENOTFOUND' ||
      error.code === 'ENETUNREACH' ||
      error.code === 'EAI_AGAIN' ||
      error.code === 'EHOSTUNREACH' ||
      error.code === 'EPIPE' ||
      error.code === 'ECONNREFUSED' ||
      error.code === 'DNS_LOOKUP_TIMEOUT'
    ) {
      return 'network';
    }

    return 'unknown';
  }

  shouldFailover(error) {
    if (!error) return false;

    if (error.code === 'NO_AVAILABLE_KEYS') {
      return true;
    }

    const status = error.response?.status;

    if (status === 400 || status === 401 || status === 403) {
      return false;
    }

    if (status === 429) {
      return true;
    }

    if (status >= 500) {
      return true;
    }

    if (this.isModelOverloadedError(error)) {
      return true;
    }

    if (
      error.code === 'ECONNRESET' ||
      error.code === 'ETIMEDOUT' ||
      error.code === 'ECONNABORTED' ||
      error.code === 'ENOTFOUND' ||
      error.code === 'ENETUNREACH' ||
      error.code === 'EAI_AGAIN' ||
      error.code === 'EHOSTUNREACH' ||
      error.code === 'EPIPE' ||
      error.code === 'ECONNREFUSED' ||
      error.code === 'DNS_LOOKUP_TIMEOUT'
    ) {
      return false;
    }

    return false;
  }

  logFailover(originalModel, newModel, requestId) {
    logInfo('Model failover activated', {
      requestId,
      originalModel,
      failoverModel: newModel,
    });
    logKeyEvent('Model Failover', {
      requestId,
      originalModel,
      failoverModel: newModel,
    });
  }
}

export default new FailoverManager();
