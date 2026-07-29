import winston from 'winston';
import 'winston-daily-rotate-file';
import path from 'path';
import fs from 'fs/promises';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
// Import sanitize utility
import { sanitizeRequest } from './utils/sanitize.js';

// Load logger configuration
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const configPath = path.join(__dirname, '../config/logger.json');
let loggerConfig = {
  logLevel: 'warning',
  console: { enabled: true, colorize: true },
  file: { enabled: true, directory: 'logs', maxSize: '20m', maxFiles: '14d' },
  categories: { request: 'warning', error: 'error', key: 'info', stream: 'info' }
};

try {
  const configData = await fs.readFile(configPath, 'utf8');
  loggerConfig = { ...loggerConfig, ...JSON.parse(configData) };
} catch (error) {
  // Use defaults if config not found
}

// Ensure logs directory exists
const logsDir = path.join(__dirname, '..', loggerConfig.file.directory);
await fs.mkdir(logsDir, { recursive: true });

// Log level priority: error=0, warning=1, info=2, debug=3
const levelPriority = { error: 0, warning: 1, info: 2, debug: 3 };
const globalLevelPriority = levelPriority[loggerConfig.logLevel] ?? 1;

// Logger level should be the most permissive to allow all messages to reach transports
// Transports will do the actual filtering
const loggerLevel = 'info'; // Allow all messages to pass to transports

// Custom formatter that adds [LEVEL] prefix
const customFormat = winston.format.printf(({ level, message, timestamp, ...metadata }) => {
  let metaStr = '';
  if (Object.keys(metadata).length > 0) {
    metaStr = ' ' + JSON.stringify(metadata);
  }
  return `${timestamp} [${level.toUpperCase()}] ${message}${metaStr}`;
});

// Create transports based on config
const transports = [];

if (loggerConfig.file.enabled) {
  transports.push(
    new winston.transports.DailyRotateFile({
      filename: path.join(logsDir, 'requests-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: loggerConfig.file.maxSize,
      maxFiles: loggerConfig.file.maxFiles,
      format: winston.format.combine(
        winston.format.timestamp(),
        customFormat
      ),
      level: loggerConfig.categories.request
    }),
    new winston.transports.DailyRotateFile({
      filename: path.join(logsDir, 'errors-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: loggerConfig.file.maxSize,
      maxFiles: loggerConfig.file.maxFiles,
      format: winston.format.combine(
        winston.format.timestamp(),
        customFormat
      ),
      level: loggerConfig.categories.error
    }),
    new winston.transports.DailyRotateFile({
      filename: path.join(logsDir, 'keys-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: loggerConfig.file.maxSize,
      maxFiles: loggerConfig.file.maxFiles,
      format: winston.format.combine(
        winston.format.timestamp(),
        customFormat
      ),
      level: loggerConfig.categories.key
    })
  );
}

if (loggerConfig.console.enabled) {
  transports.push(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp(),
        customFormat
      ),
      level: loggerConfig.logLevel
    })
  );
}

// Create loggers with permissive level to let transports filter
export const requestLogger = winston.createLogger({
  transports: transports.filter(t => t instanceof winston.transports.DailyRotateFile && t.filename.includes('requests')),
  level: loggerLevel
});

export const errorLogger = winston.createLogger({
  transports: transports.filter(t => t instanceof winston.transports.DailyRotateFile && t.filename.includes('errors')),
  level: loggerLevel
});

export const keyLogger = winston.createLogger({
  transports: transports.filter(t => t instanceof winston.transports.DailyRotateFile && t.filename.includes('keys')),
  level: loggerLevel
});

// Helper function to check if should log at level (for performance optimization)
const shouldLog = (categoryLevel) => {
  return levelPriority[categoryLevel] <= globalLevelPriority;
};

// Also check if any transport would log this level (for early return optimization)
const shouldLogAny = (categoryLevel) => {
  return levelPriority[categoryLevel] <= globalLevelPriority;
};

// Helper function to log streaming chunks
export const logStreamChunk = (requestId, chunk) => {
  if (!shouldLog('info')) return;
  try {
    const data = chunk.toString();
    requestLogger.info('Stream Chunk', {
      requestId,
      data: data.trim()
    });
  } catch (error) {
    logError(error, { context: 'Stream chunk logging', requestId });
  }
};

// Middleware for logging requests and responses
export const requestLoggingMiddleware = (req, res, next) => {
  const startTime = Date.now();
  const requestId = crypto.randomUUID();

  // Log request if level allows
  if (shouldLog(loggerConfig.categories.request)) {
    const sanitizedRequest = sanitizeRequest({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: req.body,
    });

    requestLogger.info('Incoming Request', {
      requestId,
      ...sanitizedRequest,
    });
  }

  // Track if this is a streaming request
  const isStreaming = req.body?.stream === true;

  // Override res.json for non-streaming responses
  const originalJson = res.json;
  res.json = function(data) {
    if (res.headersSent) {
      return originalJson.apply(this, arguments);
    }
    
    if (shouldLog(loggerConfig.categories.request)) {
      const responseTime = Date.now() - startTime;
      
      const sanitizedResponse = sanitizeRequest({
        statusCode: res.statusCode,
        responseTime,
        headers: res.getHeaders(),
        body: data,
      });

      requestLogger.info('Outgoing Response', {
        requestId,
        ...sanitizedResponse,
        streaming: false
      });
    }

    return originalJson.apply(this, arguments);
  };

  // Handle streaming responses
  if (isStreaming) {
    const originalWrite = res.write;
    const originalEnd = res.end;

    res.write = function(chunk) {
      if (shouldLog(loggerConfig.categories.stream)) {
        logStreamChunk(requestId, chunk);
      }
      return originalWrite.apply(this, arguments);
    };

    res.end = function(chunk) {
      if (chunk && shouldLog(loggerConfig.categories.stream)) {
        logStreamChunk(requestId, chunk);
      }
      if (shouldLog(loggerConfig.categories.request)) {
        const responseTime = Date.now() - startTime;
        requestLogger.info('Stream Ended', {
          requestId,
          responseTime,
          streaming: true
        });
      }
      return originalEnd.apply(this, arguments);
    };
  }

  next();
};

// Helper function to log key management events
export const logKeyEvent = (event, details) => {
  if (!shouldLog('info')) return;
  keyLogger.info(event, details);
};

// Helper function to log errors
export const logError = (error, context = {}) => {
  errorLogger.error(error.message, {
    stack: error.stack,
    ...context
  });
};