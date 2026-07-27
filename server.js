import express from 'express';
import dotenv from 'dotenv';
import axios from 'axios';
import keyManager from './services/KeyManager.js';
import { requestLoggingMiddleware, logError } from './services/logger.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

dotenv.config();

const app = express();
app.use(express.json({ limit: '50mb' }));
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

// Admin endpoint to add new API keys
app.post('/admin/keys', async (req, res) => {
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
    // Check for NVIDIA rate limit error in stream chunks
    buffer += chunk.toString();
    
    // Look for the NVIDIA error in SSE data format
    if (buffer.includes('Upstream error from Nvidia') && buffer.includes('ResourceExhausted')) {
      nvidiaRateLimitDetected = true;
      console.log('[Stream] NVIDIA rate limit detected in stream chunks');
      // Don't write this error to client - we'll throw to trigger retry
      break;
    }
    
    res.write(chunk);
  }
  
  if (nvidiaRateLimitDetected) {
    // Throw error to trigger retry logic
    const error = new Error('NVIDIA rate limit in stream');
    error.isNvidiaRateLimit = true;
    throw error;
  }
  
  res.end();
}

// OpenRouter proxy endpoint
app.post('/v1/chat/completions', async (req, res) => {
  const maxRetries = 3;
  let retryCount = 0;
  const isStreaming = req.body?.stream === true;

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
        trust_env: false  // Ignore environment proxy settings
      };

      // Add responseType: 'stream' for streaming requests
      if (isStreaming) {
        axiosConfig.responseType = 'stream';
      }

      // Add timeout and trust_env for all requests
      axiosConfig.timeout = 120000;  // 2 minute timeout
      axiosConfig.trust_env = false;

      const response = await axios.post(
        'https://openrouter.ai/api/v1/chat/completions',
        req.body,
        axiosConfig
      );

      // Mark the successful use of the key
      await keyManager.markKeySuccess();

      // Handle streaming response differently
      if (isStreaming) {
        return handleStreamingResponse(response, res);
      }

      return res.json(response.data);
    } catch (error) {
      // Check if NVIDIA rate limit was detected in stream chunks
      const isNvidiaRateLimitFromStream = error.isNvidiaRateLimit === true;
      
      const isRateLimit = await keyManager.markKeyError(error);

      // Check if it's a NVIDIA rate limit (for delay)
      const errorData = error.response?.data;
      const errorMessage = errorData?.error?.message || errorData?.message || JSON.stringify(errorData);
      const isNvidiaRateLimitFromResponse = typeof errorMessage === 'string' && 
        errorMessage.includes('Upstream error from Nvidia') && 
        errorMessage.includes('ResourceExhausted');
      
      const isNvidiaRateLimit = isNvidiaRateLimitFromResponse || isNvidiaRateLimitFromStream;

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
        trust_env: false
      };

      const response = await axios.get(
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
app.listen(PORT, () => {
  console.log(`OpenRouter Proxy Server running on port ${PORT}`);
});