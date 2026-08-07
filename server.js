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
  // Validate request body
  if (!req.body) {
    return res.status(400).json({
      error: { message: 'Request body is required', type: 'bad_request' }
    });
  }
  
  if (!req.body.model || !Array.isArray(req.body.messages) || req.body.messages.length === 0) {
    return res.status(400).json({
      error: { message: 'Invalid request: model and non-empty messages array required', type: 'bad_request' }
    });
  }

  // Validate message content length (prevent oversized messages)
  for (const msg of req.body.messages) {
    if (msg.content && typeof msg.content === 'string' && msg.content.length > CONFIG.MAX_MESSAGE_LENGTH) {
      return res.status(400).json({
        error: { message: `Message content exceeds maximum length of ${CONFIG.MAX_MESSAGE_LENGTH} characters`, type: 'bad_request' }
      });
    }
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
      
      const axiosConfig = {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${currentKey}`,
          'HTTP-Referer': sanitizeHeaderValue(CONFIG.HTTP_REFERER),
          'X-Title': sanitizeHeaderValue(CONFIG.SITE_NAME),
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
        return res.status(response.status || 400).json(responseData);
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
          res.write(`data: ${JSON.stringify({
            error: {
              message: error.message,
              type: 'stream_error'
            }
          })}\n\n`);
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
        return res.status(error.response?.status || 500).json({
          error: {
            message: error.response?.data?.error?.message || error.message,
            type: error.response?.data?.error?.type || 'internal_error'
          }
        });
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
      const axiosConfig = {
        headers: {
          'Authorization': `Bearer ${currentKey}`,
          'HTTP-Referer': CONFIG.HTTP_REFERER,
          'X-Title': CONFIG.SITE_NAME,
          'X-Request-ID': requestId
        },
        timeout: CONFIG.MODELS_TIMEOUT,
      };

      const response = await axiosInstance.get(
        'https://openrouter.ai/api/v1/models',
        axiosConfig
      );

      await keyManager.markKeySuccess();
      return res.json(response.data);
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

      return res.status(error.response?.status || 500).json({
        error: {
          message: error.response?.data?.error?.message || error.message,
          type: error.response?.data?.error?.type || 'internal_error'
        }
      });
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