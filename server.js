import express from 'express';
import dotenv from 'dotenv';
import axios from 'axios';
import rateLimit from 'express-rate-limit';
import https from 'https';
import { timingSafeEqual, randomUUID } from 'crypto';
import keyManager, { KeyManager } from './services/KeyManager.js';
import { requestLoggingMiddleware, logError } from './services/logger.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { mkdir } from 'fs/promises';

dotenv.config();

// Sanitize header values to prevent header injection
function sanitizeHeaderValue(value) {
  if (typeof value !== 'string') return '';
  // Strip newlines and carriage returns, limit length
  return value.replace(/[\r\n]/g, '').substring(0, 500);
}

// Model ID Normalization
// Maps OpenRouter model IDs to OpenAI-compatible format
const MODEL_ID_MAPPING = {
  // OpenRouter -> Standard mapping
  'openai/gpt-4o': 'gpt-4o',
  'openai/gpt-4o-mini': 'gpt-4o-mini',
  'openai/gpt-4-turbo': 'gpt-4-turbo',
  'openai/gpt-4': 'gpt-4',
  'openai/gpt-3.5-turbo': 'gpt-3.5-turbo',
  'anthropic/claude-3.5-sonnet': 'claude-3.5-sonnet',
  'anthropic/claude-3-opus': 'claude-3-opus',
  'anthropic/claude-3-haiku': 'claude-3-haiku',
  'google/gemini-pro': 'gemini-pro',
  'google/gemini-pro-vision': 'gemini-pro-vision',
  'meta-llama/llama-3.1-405b': 'llama-3.1-405b',
  'meta-llama/llama-3.1-70b': 'llama-3.1-70b',
  'meta-llama/llama-3.1-8b': 'llama-3.1-8b',
  'mistralai/mistral-large': 'mistral-large',
  'mistralai/mistral-nemo': 'mistral-nemo',
  'cohere/command-r-plus': 'command-r-plus',
  'cohere/command-r': 'command-r',
  // Free models
  'deepseek/deepseek-chat:free': 'deepseek-chat',
  'deepseek/deepseek-coder:free': 'deepseek-coder',
  'nvidia/nemotron-3-ultra-550b-a55b:free': 'nemotron-3-ultra',
  'qwen/qwen-2.5-72b-instruct:free': 'qwen-2.5-72b',
  'meta-llama/llama-3.1-8b-instruct:free': 'llama-3.1-8b-instruct',
  'mistralai/mistral-7b-instruct:free': 'mistral-7b-instruct',
  'google/gemma-2-9b-it:free': 'gemma-2-9b-it',
  'microsoft/phi-3-mini-128k-instruct:free': 'phi-3-mini-128k',
  'huggingface/zephyr-7b-beta:free': 'zephyr-7b-beta',
  'nousresearch/nous-hermes-2-mixtral-8x7b-dpo:free': 'nous-hermes-2-mixtral-8x7b-dpo',
  'openchat/openchat-7b:free': 'openchat-7b',
  'undi95/toppy-m-7b:free': 'toppy-m-7b',
  'gryphe/mythomax-l2-13b:free': 'mythomax-l2-13b',
  'cognitivecomputations/dolphin-2.9.2-qwen2-7b:free': 'dolphin-2.9.2-qwen2-7b',
  'sao10k/l3-70b-euryale-v2.1:free': 'l3-70b-euryale-v2.1',
  'liquid/lfm-40b:free': 'lfm-40b',
};

/**
 * Normalize OpenRouter model ID to OpenAI-compatible format
 * @param {string} openRouterId - OpenRouter model ID
 * @returns {string} Normalized model ID
 */
function normalizeModelId(openRouterId) {
  if (!openRouterId || typeof openRouterId !== 'string') {
    return openRouterId;
  }
  
  // Check direct mapping first
  if (MODEL_ID_MAPPING[openRouterId]) {
    return MODEL_ID_MAPPING[openRouterId];
  }
  
  // Try to extract base model name from provider/model format
  // e.g., "openai/gpt-4o" -> "gpt-4o"
  const parts = openRouterId.split('/');
  if (parts.length === 2) {
    const baseName = parts[1];
    // Remove :free suffix if present
    return baseName.replace(/:free$/, '');
  }
  
  // Return as-is if no mapping found
  return openRouterId;
}

/**
 * Normalize error response to OpenAI format
 * @param {Object} error - Error from OpenRouter or internal
 * @param {number} statusCode - HTTP status code
 * @returns {Object} Normalized error response
 */
function normalizeErrorResponse(error, statusCode = 500) {
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
    if (error.message) {
      message = error.message;
    } else if (error.error && error.error.message) {
      message = error.error.message;
    } else if (typeof error === 'string') {
      message = error;
    }
    
    // Extract type from OpenRouter error
    if (error.error && error.error.type) {
      type = error.error.type;
    } else if (error.type) {
      type = error.type;
    }
    
    // Extract param and code if available
    if (error.error && error.error.param) {
      param = error.error.param;
    } else if (error.param) {
      param = error.param;
    }
    
    if (error.error && error.error.code) {
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
  
  const normalizedError = {
    error: {
      message,
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
function normalizeStreamError(error, statusCode = 500) {
  const normalized = normalizeErrorResponse(error, statusCode);
  return `data: ${JSON.stringify(normalized)}\n\n`;
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
  }
  
  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    errors.push('Field "messages" is required and must be a non-empty array');
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

// Configuration constants
const CONFIG = {
  PORT: process.env.PORT || 3000,
  BODY_LIMIT: process.env.BODY_LIMIT || '5mb',
  MAX_MESSAGE_LENGTH: parseInt(process.env.MAX_MESSAGE_LENGTH || '100000', 10),
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
  RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
  AXIOS_TIMEOUT: parseInt(process.env.AXIOS_TIMEOUT || '120000', 10),
  AXIOS_MAX_SOCKETS: parseInt(process.env.AXIOS_MAX_SOCKETS || '50', 10),
  AXIOS_MAX_FREE_SOCKETS: parseInt(process.env.AXIOS_MAX_FREE_SOCKETS || '10', 10),
  AXIOS_KEEPALIVE_TIMEOUT: parseInt(process.env.AXIOS_KEEPALIVE_TIMEOUT || '60000', 10),
  AXIOS_FREE_SOCKET_TIMEOUT: parseInt(process.env.AXIOS_FREE_SOCKET_TIMEOUT || '30000', 10),
  MAX_RETRIES: parseInt(process.env.MAX_RETRIES || '3', 10),
  RETRY_DELAY_MS: parseInt(process.env.RETRY_DELAY_MS || '1000', 10),
  SSE_BUFFER_LIMIT: parseInt(process.env.SSE_BUFFER_LIMIT || String(10 * 1024 * 1024), 10),
  MODELS_TIMEOUT: parseInt(process.env.MODELS_TIMEOUT || '30000', 10),
  HTTP_REFERER: process.env.HTTP_REFERER || 'http://localhost:3000',
  SITE_NAME: process.env.SITE_NAME || 'OpenRouterProxy',
  // Admin endpoint stricter rate limiting
  ADMIN_RATE_LIMIT_WINDOW_MS: parseInt(process.env.ADMIN_RATE_LIMIT_WINDOW_MS || '60000', 10),
  ADMIN_RATE_LIMIT_MAX: parseInt(process.env.ADMIN_RATE_LIMIT_MAX || '10', 10)
};

// Create logs directory
const __dirname = dirname(fileURLToPath(import.meta.url));
const logsDir = join(__dirname, 'logs');
try {
  await mkdir(logsDir, { recursive: true });
} catch (error) {
  console.error('Error creating logs directory:', error);
}

// Create axios instance with connection pooling
const keepaliveAgent = new https.Agent({
  keepAlive: true,
  maxSockets: CONFIG.AXIOS_MAX_SOCKETS,
  maxFreeSockets: CONFIG.AXIOS_MAX_FREE_SOCKETS,
  timeout: CONFIG.AXIOS_KEEPALIVE_TIMEOUT,
  freeSocketTimeout: CONFIG.AXIOS_FREE_SOCKET_TIMEOUT
});

const axiosInstance = axios.create({
  httpsAgent: keepaliveAgent,
  timeout: CONFIG.AXIOS_TIMEOUT,
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
  await initializeKeys();
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
  const MAX_EVENT_SIZE = 1024 * 1024; // 1 MB per event
  let buffer = '';
  let nvidiaRateLimitDetected = false;
  let clientClosed = false;

  // Use AbortController to abort upstream request on client disconnect
  req.on('close', () => {
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
            const isNvidiaRateLimit = KeyManager.isNvidiaRateLimitError({
              response: { data: data, status: 200, headers: {} }
            });
            if (typeof errorMsg === 'string' && isNvidiaRateLimit) {
              nvidiaRateLimitDetected = true;
              logError(new Error('NVIDIA rate limit detected in SSE chunk'), { 
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
  const maxRetries = CONFIG.MAX_RETRIES;
  let retryCount = 0;
  const isStreaming = req.body?.stream === true;
  let streamDataSent = false;

  while (retryCount < maxRetries) {
    try {
      // Get the current key or rotate if needed
      const currentKey = await keyManager.getKey();
      
      // Create AbortController for client disconnect handling
      const abortController = new AbortController();
      
      // Forward client headers if provided, fallback to env vars
      const clientReferer = req.headers['http-referer'] || req.headers['referer'];
      const clientTitle = req.headers['x-title'];
      
      const axiosConfig = {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${currentKey}`,
          'HTTP-Referer': sanitizeHeaderValue(clientReferer || CONFIG.HTTP_REFERER),
          'X-Title': sanitizeHeaderValue(clientTitle || CONFIG.SITE_NAME),
          'X-Request-ID': requestId
        },
        timeout: CONFIG.AXIOS_TIMEOUT,
        signal: abortController.signal
      };

      // Add responseType: 'stream' for streaming requests
      if (isStreaming) {
        axiosConfig.responseType = 'stream';
      }

      const response = await axiosInstance.post(
        'https://openrouter.ai/api/v1/chat/completions',
        req.body,
        axiosConfig
      );

      // Check for error in response body (OpenRouter returns 200 with error in body for model errors)
      const responseData = response.data;
      if (responseData?.error?.message) {
        const errorMessage = responseData.error.message;
        
        // Use centralized NVIDIA rate limit detection
        const isNvidiaRateLimit = KeyManager.isNvidiaRateLimitError({
          response: {
            data: responseData,
            status: 200,
            headers: response.headers
          }
        });
        
        if (isNvidiaRateLimit) {
          logError(new Error('NVIDIA rate limit detected in response'), { 
            context: 'Response', 
            errorMessage: errorMessage.substring(0, 200) 
          });
          // Create an error that will be caught by the catch block
          const error = new Error('NVIDIA rate limit in response');
          error.response = {
            data: responseData,
            status: 200,
            headers: response.headers
          };
          error.isNvidiaRateLimit = true;
          throw error;
        }
        
        // For other errors (validation, model not found, etc.), don't mark key as success
        // but also don't retry - just return the error to client
        const statusCode = response.status || 400;
        return res.status(statusCode).json(normalizeErrorResponse(responseData, statusCode));
      }

      // Mark the successful use of the key (only on true success, no error in body)
      await keyManager.markKeySuccess();

      // Handle streaming response differently
      if (isStreaming) {
        // Wrap res.write to track if data was sent
        const originalWrite = res.write;
        res.write = function(chunk) {
          if (chunk && chunk.length > 0) {
            streamDataSent = true;
          }
          return originalWrite.apply(this, arguments);
        };
        
        await handleStreamingResponse(response, req, res, abortController);
        return;
      }

      return res.json(responseData);
    } catch (error) {
      
      const isRateLimit = await keyManager.markKeyError(error);

      // Check if it's a NVIDIA rate limit (for delay) - more robust detection
      const errorData = error.response?.data;
      const safeStringify = (obj) => {
        try {
          return JSON.stringify(obj);
        } catch {
          return String(obj);
        }
      };
      const errorMessage = errorData?.error?.message || errorData?.message || safeStringify(errorData);
      
      // Use centralized NVIDIA rate limit detection
      const isNvidiaRateLimitFromResponse = KeyManager.isNvidiaRateLimitError({
        response: {
          data: errorData,
          status: error.response?.status,
          headers: error.response?.headers
        }
      });
      
      const isNvidiaRateLimitFromError = error.isNvidiaRateLimit === true;
      const isNvidiaRateLimit = isNvidiaRateLimitFromResponse || isNvidiaRateLimitFromError;

      // Handle streaming errors - retry on rate limits, otherwise end stream
      if (isStreaming) {
        // Don't retry if we've already sent data to the client (would cause duplicate/interleaved streams)
        if (streamDataSent) {
          logError(new Error('[Stream] Data already sent, skipping retry to avoid duplicate streams'), {
            context: 'Stream Retry',
            streamDataSent: true
          });
        } else if ((isRateLimit || isNvidiaRateLimit) && retryCount < maxRetries - 1) {
          // Retry on rate limit for streaming too
          retryCount++;
          
          // Add delay for NVIDIA rate limits
          if (isNvidiaRateLimit) {
            const msg = `[Retry] NVIDIA rate limit hit on stream, waiting ${CONFIG.RETRY_DELAY_MS}ms before retry...`;
            logError(new Error(msg), { context: 'Stream Retry', retryCount, delayMs: CONFIG.RETRY_DELAY_MS });
            await new Promise(resolve => setTimeout(resolve, CONFIG.RETRY_DELAY_MS));
          }
          
          // Continue to next iteration of while loop (retry)
          continue;
        }
        
        // Non-retryable error or max retries reached - end stream with error
        if (!res.writableEnded) {
          res.write(normalizeStreamError(error, error.response?.status || 500));
          res.end();
        }
        return;
      }

      // Only retry on rate limits or server errors
      if ((isRateLimit || error.response?.status >= 500) && retryCount < maxRetries - 1) {
        retryCount++;
        
        // Add delay for NVIDIA rate limits (already detected above)
        if (isRateLimit && isNvidiaRateLimit) {
          const msg = `[Retry] NVIDIA rate limit hit, waiting ${CONFIG.RETRY_DELAY_MS}ms before retry...`;
          logError(new Error(msg), { context: 'Retry', retryCount, delayMs: CONFIG.RETRY_DELAY_MS });
          await new Promise(resolve => setTimeout(resolve, CONFIG.RETRY_DELAY_MS));
        }
        continue;
      }

      logError(error, { 
        context: 'Chat completions',
        retryCount,
        statusCode: error.response?.status,
        streaming: isStreaming
      });

      // For non-streaming requests, send error response
      if (!isStreaming) {
        const statusCode = error.response?.status || 500;
        return res.status(statusCode).json(normalizeErrorResponse(error, statusCode));
      }
      
      // For streaming, we've already ended the response above
      return;
    }
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
  const maxRetries = CONFIG.MAX_RETRIES;
  let retryCount = 0;

  while (retryCount < maxRetries) {
    try {
      const currentKey = await keyManager.getKey();
      
      // Forward client headers if provided, fallback to env vars
      const clientReferer = req.headers['http-referer'] || req.headers['referer'];
      const clientTitle = req.headers['x-title'];
      
      const axiosConfig = {
        headers: {
          'Authorization': `Bearer ${currentKey}`,
          'HTTP-Referer': sanitizeHeaderValue(clientReferer || CONFIG.HTTP_REFERER),
          'X-Title': sanitizeHeaderValue(clientTitle || CONFIG.SITE_NAME),
          'X-Request-ID': requestId
        },
        timeout: CONFIG.MODELS_TIMEOUT,
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
      const isRateLimit = await keyManager.markKeyError(error);

      if ((isRateLimit || error.response?.status >= 500) && retryCount < maxRetries - 1) {
        retryCount++;
        continue;
      }

      logError(error, { 
        context: 'Models endpoint',
        retryCount,
        statusCode: error.response?.status
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
  
  const requestId = randomUUID();
  const maxRetries = CONFIG.MAX_RETRIES;
  let retryCount = 0;
  
  // Transform Anthropic format to OpenAI format
  const openAIBody = {
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
    max_tokens: req.body.max_tokens,
    temperature: req.body.temperature,
    top_p: req.body.top_p,
    stop: req.body.stop,
    tools: req.body.tools,
    tool_choice: req.body.tool_choice,
  };
  
  // Add system message if provided (Anthropic has separate system param)
  if (req.body.system) {
    openAIBody.messages.unshift({ role: 'system', content: req.body.system });
  }
  
  while (retryCount < maxRetries) {
    try {
      const currentKey = await keyManager.getKey();
      
      // Create AbortController for client disconnect handling
      const abortController = new AbortController();
      
      // Forward client headers if provided, fallback to env vars
      const clientReferer = req.headers['http-referer'] || req.headers['referer'];
      const clientTitle = req.headers['x-title'];
      
      const axiosConfig = {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${currentKey}`,
          'HTTP-Referer': sanitizeHeaderValue(clientReferer || CONFIG.HTTP_REFERER),
          'X-Title': sanitizeHeaderValue(clientTitle || CONFIG.SITE_NAME),
          'X-Request-ID': requestId
        },
        timeout: CONFIG.AXIOS_TIMEOUT,
        signal: abortController.signal
      };
      
      // Add responseType: 'stream' for streaming requests
      if (openAIBody.stream) {
        axiosConfig.responseType = 'stream';
      }
      
      const response = await axiosInstance.post(
        'https://openrouter.ai/api/v1/chat/completions',
        openAIBody,
        axiosConfig
      );
      
      // Check for error in response body
      const responseData = response.data;
      if (responseData?.error?.message) {
        const errorMessage = responseData.error.message;
        
        const isNvidiaRateLimit = KeyManager.isNvidiaRateLimitError({
          response: {
            data: responseData,
            status: 200,
            headers: response.headers
          }
        });
        
        if (isNvidiaRateLimit) {
          logError(new Error('NVIDIA rate limit detected in response'), { 
            context: 'Anthropic Response', 
            errorMessage: errorMessage.substring(0, 200) 
          });
          const error = new Error('NVIDIA rate limit in response');
          error.response = { data: responseData, status: 200, headers: response.headers };
          error.isNvidiaRateLimit = true;
          throw error;
        }
        
        const statusCode = response.status || 400;
        return res.status(statusCode).json(normalizeErrorResponse(responseData, statusCode));
      }
      
      await keyManager.markKeySuccess();
      
      // Transform OpenAI response to Anthropic format
      const anthropicResponse = {
        id: responseData.id?.replace('chatcmpl-', 'msg_') || `msg_${Date.now()}`,
        type: 'message',
        role: 'assistant',
        content: [],
        model: responseData.model,
        stop_reason: responseData.choices?.[0]?.finish_reason === 'tool_calls' ? 'tool_use' : 'end_turn',
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
          anthropicResponse.content.push({
            type: 'tool_use',
            id: tc.id,
            name: tc.function.name,
            input: JSON.parse(tc.function.arguments)
          });
        });
      }
      
      // Handle streaming
      if (openAIBody.stream) {
        // For streaming, we need to transform SSE events
        // This is complex - for now, return a simple response
        // TODO: Implement full streaming transformation
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        
        // Send initial event
        res.write(`data: ${JSON.stringify({ type: 'message_start', message: anthropicResponse })}\n\n`);
        
        // For now, just forward the stream - proper transformation would require parsing each SSE event
        for await (const chunk of response.data) {
          res.write(chunk);
        }
        res.write(`data: ${JSON.stringify({ type: 'message_delta', delta: { stop_reason: 'end_turn' } })}\n\n`);
        res.write('data: [DONE]\n\n');
        res.end();
        return;
      }
      
      return res.json(anthropicResponse);
      
    } catch (error) {
      const isRateLimit = await keyManager.markKeyError(error);
      
      const errorData = error.response?.data;
      const safeStringify = (obj) => {
        try { return JSON.stringify(obj); } catch { return String(obj); }
      };
      const errorMessage = errorData?.error?.message || errorData?.message || safeStringify(errorData);
      
      const isNvidiaRateLimitFromResponse = KeyManager.isNvidiaRateLimitError({
        response: { data: errorData, status: error.response?.status, headers: error.response?.headers }
      });
      
      const isNvidiaRateLimitFromError = error.isNvidiaRateLimit === true;
      const isNvidiaRateLimit = isNvidiaRateLimitFromResponse || isNvidiaRateLimitFromError;
      
      if ((isRateLimit || isNvidiaRateLimit) && retryCount < maxRetries - 1) {
        retryCount++;
        if (isNvidiaRateLimit) {
          const msg = `[Retry] NVIDIA rate limit hit on Anthropic, waiting ${CONFIG.RETRY_DELAY_MS}ms before retry...`;
          logError(new Error(msg), { context: 'Anthropic Retry', retryCount, delayMs: CONFIG.RETRY_DELAY_MS });
          await new Promise(resolve => setTimeout(resolve, CONFIG.RETRY_DELAY_MS));
        }
        continue;
      }
      
      logError(error, { 
        context: 'Anthropic messages',
        retryCount,
        statusCode: error.response?.status,
      });
      
      const statusCode = error.response?.status || 500;
      return res.status(statusCode).json(normalizeErrorResponse(error, statusCode));
    }
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logError(err, { 
    context: 'Global error handler',
    url: req.url,
    method: req.method
  });
  
  res.status(500).json({
    error: {
      message: 'Internal server error',
      type: 'internal_error'
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