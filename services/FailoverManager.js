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

  _extractErrorMessage(error) {
    const data = error?.response?.data || error;
    if (!data || typeof data !== 'object') return '';

    const safeStringify = (obj) => {
      try {
        return JSON.stringify(obj);
      } catch {
        return String(obj);
      }
    };

    return data.error?.message || data.message || safeStringify(data);
  }

  _extractMetadataErrorType(error) {
    const data = error?.response?.data || error;
    if (!data || typeof data !== 'object') return null;
    return data.error?.metadata?.error_type || data.metadata?.error_type || null;
  }

  isMetadataOverloadedError(error) {
    const errorType = this._extractMetadataErrorType(error);
    if (!errorType || typeof errorType !== 'string') return false;

    const lower = errorType.toLowerCase();
    return (
      lower.includes('overloaded') ||
      lower.includes('capacity') ||
      lower.includes('provider_overloaded') ||
      lower.includes('rate_limit') ||
      lower.includes('temporarily_unavailable') ||
      lower.includes('service_unavailable') ||
      lower.includes('timeout')
    );
  }

  isModelOverloadedError(error) {
    const errorMessage = this._extractErrorMessage(error);
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

  isUpstreamServiceError(error) {
    const errorMessage = this._extractErrorMessage(error);
    if (typeof errorMessage !== 'string') return false;

    const lower = errorMessage.toLowerCase();

    // Detect OpenRouter's upstream error format: "Upstream error from <provider>: <details>"
    // This is different from our own sanitized "Upstream service error" which is short
    // Real upstream errors are longer and contain provider info + specific error details
    const isRealUpstreamError = lower.includes('upstream error from') && 
      (lower.includes('overloaded') ||
       lower.includes('capacity') ||
       lower.includes('temporarily unavailable') ||
       lower.includes('service unavailable') ||
       lower.includes('rate limit') ||
       lower.includes('limit reached') ||
       lower.includes('timeout') ||
       lower.includes('try again'));

    // Also catch generic "upstream" errors that are detailed (not our short sanitized version)
    const isDetailedUpstreamError = lower.startsWith('upstream ') && 
      errorMessage.length > 30; // Our sanitized message is exactly "Upstream service error" (21 chars)

    return isRealUpstreamError || isDetailedUpstreamError;
  }

  isModelCapabilityError(error) {
    const errorMessage = this._extractErrorMessage(error);
    if (typeof errorMessage !== 'string') return false;

    const lower = errorMessage.toLowerCase();

    return (
      lower.includes('no endpoints found that support') ||
      lower.includes('tool use') ||
      lower.includes('does not support') ||
      lower.includes('unsupported') ||
      lower.includes('provider routing')
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

    if (status === 404 && this.isModelCapabilityError(error)) {
      return 'capability_error';
    }

    if (status === 429) {
      return 'rate_limit';
    }

    if (status >= 500) {
      return 'server_error';
    }

    if (this.isUpstreamServiceError(error)) {
      return 'upstream_service_error';
    }

    if (this.isMetadataOverloadedError(error)) {
      return 'metadata_overloaded';
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

    if (status === 404 && this.isModelCapabilityError(error)) {
      return true;
    }

    if (this.isModelOverloadedError(error)) {
      return true;
    }

    if (this.isUpstreamServiceError(error)) {
      return true;
    }

    if (this.isMetadataOverloadedError(error)) {
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
