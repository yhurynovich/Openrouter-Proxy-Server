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
  categories: { request: 'warning', error: 'error', key: 'info', stream: 'debug' }
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

// Custom formatter that adds [LEVEL] prefix
const customFormat = winston.format.printf(({ level, message, timestamp, ...metadata }) => {
  let metaStr = '';
  if (Object.keys(metadata).length > 0) {
    metaStr = ' ' + JSON.stringify(metadata);
  }
  return `${timestamp} [${level.toUpperCase()}] ${message}${metaStr}`;
});

// Create explicit transports for each category
const requestTransport = new winston.transports.DailyRotateFile({
  filename: path.join(logsDir, 'requests-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxSize: loggerConfig.file.maxSize,
  maxFiles: loggerConfig.file.maxFiles,
  format: winston.format.combine(
    winston.format.timestamp(),
    customFormat
  ),
  level: loggerConfig.categories.request
});

const errorTransport = new winston.transports.DailyRotateFile({
  filename: path.join(logsDir, 'errors-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxSize: loggerConfig.file.maxSize,
  maxFiles: loggerConfig.file.maxFiles,
  format: winston.format.combine(
    winston.format.timestamp(),
    customFormat
  ),
  level: loggerConfig.categories.error
});

const keyTransport = new winston.transports.DailyRotateFile({
  filename: path.join(logsDir, 'keys-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxSize: loggerConfig.file.maxSize,
  maxFiles: loggerConfig.file.maxFiles,
  format: winston.format.combine(
    winston.format.timestamp(),
    customFormat
  ),
  level: loggerConfig.categories.key
});

const streamTransport = new winston.transports.DailyRotateFile({
  filename: path.join(logsDir, 'streams-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxSize: loggerConfig.file.maxSize,
  maxFiles: loggerConfig.file.maxFiles,
  format: winston.format.combine(
    winston.format.timestamp(),
    customFormat
  ),
  level: loggerConfig.categories.stream
});

// Console transports - separate for general and error logs
const consoleTransport = loggerConfig.console.enabled ? new winston.transports.Console({
  format: winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp(),
    customFormat
  ),
  level: loggerConfig.logLevel
}) : null;

// Dedicated error console transport - ensures errors always appear in console
const errorConsoleTransport = loggerConfig.console.enabled ? new winston.transports.Console({
  format: winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp(),
    customFormat
  ),
  level: 'error' // Always log errors to console
}) : null;

// Create loggers with explicit transports
export const requestLogger = winston.createLogger({
  transports: [requestTransport].concat(consoleTransport ? [consoleTransport] : []),
  level: 'info'
});

export const errorLogger = winston.createLogger({
  transports: [errorTransport].concat(errorConsoleTransport ? [errorConsoleTransport] : []),
  level: 'info'
});

export const keyLogger = winston.createLogger({
  transports: [keyTransport].concat(consoleTransport ? [consoleTransport] : []),
  level: 'info'
});

export const streamLogger = winston.createLogger({
  transports: [streamTransport].concat(consoleTransport ? [consoleTransport] : []),
  level: 'debug'
});

// Helper function to check if should log at level (for performance optimization)
const shouldLog = (categoryLevel) => {
  return levelPriority[categoryLevel] <= globalLevelPriority;
};

// Helper function to log streaming chunks (at debug level to reduce volume)
export const logStreamChunk = (requestId, chunk) => {
  if (!shouldLog('debug')) return;
  try {
    const data = chunk.toString();
    streamLogger.debug('Stream Chunk', {
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
  // Sanitize context to prevent sensitive data leakage
  const sanitizedContext = sanitizeRequest(context);
  errorLogger.error(error.message, {
    stack: error.stack,
    ...sanitizedContext
  });
};