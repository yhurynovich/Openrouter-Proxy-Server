import express from 'express';
import dotenv from 'dotenv';
import axios from 'axios';
import rateLimit from 'express-rate-limit';
import https from 'https';
import keyManager from './services/KeyManager.js';
import { requestLoggingMiddleware, logError } from './services/logger.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

dotenv.config();

// Create axios instance with connection pooling
const keepaliveAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 50,
  maxFreeSockets: 10,
  timeout: 60000,
  freeSocketTimeout: 30000
});

const axiosInstance = axios.create({
  httpsAgent: keepaliveAgent,
  timeout: 120000,
});

const app = express();

// Reduce body limit to prevent DoS
app.use(express.json({ limit: '5mb' }));

// Rate limiting middleware (100 requests per minute per IP)
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { message: 'Too many requests, please try again later', type: 'rate_limit_exceeded' } }
});
app.use(limiter);

app.use(requestLoggingMiddleware);

// Create logs directory
const __dirname = dirname(fileURLToPath(import.meta.url));
const logsDir = join(__dirname, 'logs');
import { mkdir } from 'fs/promises';
try {
  await mkdir(logsDir, { recursive: true });
} catch (error) {
  console.error('Error creating logs directory:', error);
}

// Initialize with default key(s) if provided
const initializeKeys = async () => {
  try {
    const defaultKeys = process.env.OPENROUTER_API_KEYS;
    if (defaultKeys) {
      // Support comma-separated multiple keys
      const keys = defaultKeys.split(',').map(k => k.trim()).filter(k => k);
      for (const key of keys) {
        await keyManager.addKey(key);
      }
    }
    await keyManager.initialize();
  } catch (error) {
    logError(error, { context: 'Key initialization' });
  }
};

// Wait for initialization before accepting requests
await initializeKeys();

// Admin authentication middleware
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const adminAuth = (req, res, next) => {
  if (!ADMIN_SECRET) {
    return res.status(503).json({ error: 'Admin secret not configured' });
  }
  if (req.headers['x-admin-secret'] !== ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

// Admin endpoint to add new API keys
app.post('/admin/keys', adminAuth, async (req, res) => {
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
async function handleStreamingResponse(axiosResponse, res) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  let buffer = '';
  let nvidiaRateLimitDetected = false;

  for await (const chunk of axiosResponse.data) {
    const chunkStr = chunk.toString();
    buffer += chunkStr;
    
    // Parse SSE format: each event is separated by \n\n
    // Each event has "data: " prefix
    const events = buffer.split('\n\n');
    
    // Keep the last incomplete event in buffer
    buffer = events.pop() || '';
    
    for (const event of events) {
      // Check if this is a data event
      if (event.startsWith('data: ')) {
        const dataStr = event.slice(6).trim(); // Remove "data: " prefix
        
        // Check for [DONE] marker
        if (dataStr === '[DONE]') {
          res.write(chunkStr);
          continue;
        }
        
        try {
          const data = JSON.parse(dataStr);
          
          // Check for NVIDIA rate limit error in the chunk
          if (data.error && data.error.message) {
            const errorMsg = data.error.message;
            if (typeof errorMsg === 'string' && 
                errorMsg.includes('Upstream error from Nvidia') && 
                errorMsg.includes('ResourceExhausted')) {
              nvidiaRateLimitDetected = true;
              logError(new Error('NVIDIA rate limit detected in SSE chunk'), { 
                context: 'Stream', 
                errorMessage: errorMsg 
              });
              break; // Stop processing, will handle after loop
            }
          }
        } catch (e) {
          // Not valid JSON, just forward it
        }
      }
      
      // Write the event to client
      res.write(event + '\n\n');
    }
    
    if (nvidiaRateLimitDetected) {
      break;
    }
  }
  
  if (nvidiaRateLimitDetected) {
    // Don't throw - write error to stream and end gracefully
    // This allows the retry logic in the caller to work properly
    if (!res.writableEnded) {
      res.write(`data: ${JSON.stringify({
        error: {
          message: 'NVIDIA rate limit exceeded',
          type: 'stream_error'
        }
      })}\n\n`);
      res.end();
    }
    // Return a special value to indicate rate limit was handled
    return { rateLimitHandled: true };
  }
  
  // Write any remaining buffer
  if (buffer) {
    res.write(buffer);
  }
  
  res.end();
}

// Create connection pool agent for axios
import { Agent } from 'https';
const httpAgent = new Agent({ keepAlive: true, maxSockets: 50 });

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
  
  const maxRetries = 3;
  let retryCount = 0;
  const isStreaming = req.body?.stream === true;
  let isNvidiaRateLimitFromStream = false;

  while (retryCount < maxRetries) {
    try {
      // Get the current key or rotate if needed
      const currentKey = await keyManager.getKey();
      
      const axiosConfig = {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${currentKey}`,
          'HTTP-Referer': process.env.HTTP_REFERER || 'http://localhost:3000',
          'X-Title': process.env.SITE_NAME || 'OpenRouterProxy'
        },
        timeout: 120000,  // 2 minute timeout
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
        
        // Robust NVIDIA rate limit detection - multiple patterns
        const isNvidiaRateLimit = typeof errorMessage === 'string' && 
          (errorMessage.includes('Upstream error from Nvidia') || 
           errorMessage.includes('upstream error from nvidia')) && 
          (errorMessage.includes('ResourceExhausted') || 
           errorMessage.includes('resource exhausted') ||
           errorMessage.includes('Worker local total request limit reached') ||
           errorMessage.includes('rate limit') ||
           errorMessage.includes('Resource Exhausted'));
        
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
      }

      // Mark the successful use of the key
      await keyManager.markKeySuccess();

      // Handle streaming response differently
      if (isStreaming) {
        const streamResult = await handleStreamingResponse(response, res);
        // Check if NVIDIA rate limit was handled in streaming
        if (streamResult?.rateLimitHandled) {
          // Set a flag to trigger retry logic
          isNvidiaRateLimitFromStream = true;
        }
        return;
      }

      return res.json(responseData);
    } catch (error) {
      // Check if NVIDIA rate limit was detected in stream chunks
      const isNvidiaRateLimitFromError = error.isNvidiaRateLimit === true;
      
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
      const isNvidiaRateLimitFromResponse = typeof errorMessage === 'string' && 
        errorMessage.includes('Upstream error from Nvidia') && 
        (errorMessage.includes('ResourceExhausted') || 
         errorMessage.includes('rate limit') ||
         errorMessage.includes('limit reached'));
      
      const isNvidiaRateLimit = isNvidiaRateLimitFromResponse || isNvidiaRateLimitFromError || isNvidiaRateLimitFromStream;

      // Handle streaming errors - retry on rate limits, otherwise end stream
      if (isStreaming) {
        if ((isRateLimit || isNvidiaRateLimitFromStream) && retryCount < maxRetries - 1) {
          // Retry on rate limit for streaming too
          retryCount++;
          
          // Add 1 second delay for NVIDIA rate limits
          if (isNvidiaRateLimit) {
            console.log('[Retry] NVIDIA rate limit hit on stream, waiting 1 second before retry...');
            await new Promise(resolve => setTimeout(resolve, 1000));
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
        
        // Add 1 second delay for NVIDIA rate limits (already detected above)
        if (isRateLimit && isNvidiaRateLimit) {
          console.log('[Retry] NVIDIA rate limit hit, waiting 1 second before retry...');
          await new Promise(resolve => setTimeout(resolve, 1000));
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
let isReady = false;
initializeKeys().then(() => {
  isReady = true;
}).catch(err => {
  console.error('Key initialization failed:', err);
  // Server still starts but health will report not ready
});

app.get('/health', (req, res) => {
  res.json({
    status: isReady ? 'ready' : 'not ready',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Models endpoint
app.get('/v1/models', async (req, res) => {
  const maxRetries = 3;
  let retryCount = 0;

  while (retryCount < maxRetries) {
    try {
      const currentKey = await keyManager.getKey();
      const axiosConfig = {
        headers: {
          'Authorization': `Bearer ${currentKey}`,
          'HTTP-Referer': process.env.HTTP_REFERER || 'http://localhost:3000',
          'X-Title': process.env.SITE_NAME || 'OpenRouterProxy'
        },
        timeout: 30000,  // 30 second timeout
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

const PORT = process.env.PORT || 3000;
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