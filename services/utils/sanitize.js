export const sanitizeRequest = (request) => {
  const sanitized = JSON.parse(JSON.stringify(request)); // Deep clone
  
  // Redact Authorization header
  if (sanitized.headers?.Authorization) {
    sanitized.headers.Authorization = 'REDACTED';
  }
  
  // Redact x-api-key header
  if (sanitized.headers?.['x-api-key']) {
    sanitized.headers['x-api-key'] = 'REDACTED';
  }

  // Redact any apiKey in body
  if (sanitized.body?.apiKey) {
    sanitized.body.apiKey = 'REDACTED';
  }
  
  // Redact api_key in body (OpenRouter format)
  if (sanitized.body?.api_key) {
    sanitized.body.api_key = 'REDACTED';
  }
  
  // Redact key in body (other formats)
  if (sanitized.body?.key) {
    sanitized.body.key = 'REDACTED';
  }

  return sanitized;
};