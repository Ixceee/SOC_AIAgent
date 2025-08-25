const { createClient } = require('redis');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');

// Configuration
const REDIS_CONFIG = {
  url: process.env.REDIS_URL || 'redis://redis:6379',
  socket: {
    reconnectStrategy: (retries) => Math.min(retries * 100, 5000)
  }
};

const redisClient = createClient(REDIS_CONFIG);
let isRedisReady = false;

// Connection handlers
redisClient.on('connect', () => console.log('Redis connecting...'));
redisClient.on('ready', () => {
  isRedisReady = true;
  console.log('Redis connected');
});
redisClient.on('error', (err) => console.error('Redis error:', err));
redisClient.on('end', () => {
  isRedisReady = false;
  console.log('Redis disconnected');
});

// Connection function
const connectRedis = async () => {
  try {
    await redisClient.connect();
  } catch (err) {
    console.error('Redis connection failed, retrying...');
    setTimeout(connectRedis, 5000);
  }
};

// Initialize connection
(async () => { await connectRedis(); })();

// Analysis functions
const analyzeWithAI = async (alert) => {
  try {
    const response = await axios.post(
      `${process.env.OLLAMA_HOST || 'http://ollama:11434'}/api/generate`,
      {
        model: process.env.OLLAMA_MODEL || "llama3:8b-instruct-q4_0",
        prompt: `Analyze security alert and return JSON: ${JSON.stringify(alert)}`,
        format: "json"
      },
      { timeout: 5000 }
    );
    return response.data?.response;
  } catch (error) {
    console.error('AI analysis failed:', error);
    return null;
  }
};

module.exports = {
  analyze: async (alert) => {
    const cacheKey = `alert:${alert.id || uuidv4()}`;
    
    try {
      // Try cache first
      if (isRedisReady) {
        const cached = await redisClient.get(cacheKey);
        if (cached) return { ...JSON.parse(cached), cached: true };
      }

      // AI analysis
      const result = await analyzeWithAI(alert) || {
        risk: 'medium',
        confidence: 0.5,
        reason: 'Fallback analysis'
      };

      // Cache result
      if (isRedisReady) {
        await redisClient.setEx(
          cacheKey,
          process.env.REDIS_TTL || 3600,
          JSON.stringify(result)
        );
      }

      return result;
    } catch (err) {
      console.error('Analysis failed:', err);
      return {
        risk: 'unknown',
        confidence: 0,
        error: err.message
      };
    }
  },

  ping: async () => {
    if (!isRedisReady) return false;
    try {
      return await redisClient.ping();
    } catch (err) {
      return false;
    }
  },

  disconnect: async () => {
    if (redisClient.isOpen) await redisClient.quit();
  }
};