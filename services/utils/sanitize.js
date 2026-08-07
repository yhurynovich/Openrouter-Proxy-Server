export const sanitizeRequest = (request) => {
  // Use structuredClone for deep clone (handles circular refs, BigInt, etc)
  // Fallback to JSON for older environments
  let sanitized;
  try {
    if (typeof structuredClone === 'function') {
      sanitized = structuredClone(request);
    } else {
      sanitized = JSON.parse(JSON.stringify(request));
    }
  } catch {
    // If both fail (circular refs, etc.), return minimal safe object
    sanitized = { 
      _sanitizationFailed: true,
      method: request?.method,
      url: request?.url 
    };
  }
  
  // Recursively redact sensitive fields
  const redact = (obj, path = '') => {
    if (!obj || typeof obj !== 'object') return obj;
    
    if (Array.isArray(obj)) {
      return obj.map((item, i) => redact(item, `${path}[${i}]`));
    }
    
    const result = { ...obj };
    for (const [k, v] of Object.entries(result)) {
      const fullPath = path ? `${path}.${k}` : k;
      const lowerKey = k.toLowerCase();
      
      // Redact known sensitive keys (specific patterns including generic 'key')
      if (['authorization', 'x-api-key', 'apikey', 'api_key', 'key', 'secret', 'password', 'token', 'access_token', 'refresh_token', 'admin_secret', 'x-admin-secret'].includes(lowerKey)) {
        result[k] = 'REDACTED';
      } else if (typeof v === 'object' && v !== null) {
        // Recurse into nested objects
        result[k] = redact(v, fullPath);
      }
    }
    return result;
  };
  
  return redact(sanitized);
};