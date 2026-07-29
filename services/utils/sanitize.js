export const sanitizeRequest = (request) => {
  // Use structuredClone for deep clone (handles circular refs, BigInt, etc)
  // Fallback to JSON for older environments
  const sanitized = (typeof structuredClone === 'function')
    ? structuredClone(request)
    : (() => {
        try {
          return JSON.parse(JSON.stringify(request));
        } catch {
          // If circular ref or other issue, return a safe minimal object
          return { ...request };
        }
      })();
  
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
      
      // Redact known sensitive keys
      if (['authorization', 'x-api-key', 'apikey', 'api_key', 'key', 'apikey'].includes(lowerKey)) {
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