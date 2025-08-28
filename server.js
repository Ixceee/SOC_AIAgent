require('dotenv').config();
const cors = require('cors');
const express = require('express');
const http = require('http');
const fs = require('fs');
const path = require('path');
const morgan = require('morgan');
const app = express();

// Middleware
app.use(cors()); // ✅ CORS enabled
app.options('*', cors());
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));


app.options('*', (req, res) => {
  console.log('✅ Preflight OPTIONS request received');
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.sendStatus(200);
});

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ================= DEBUG ROUTES =================
app.get('/debug', (req, res) => {
  res.json({ 
    message: 'Debug endpoint working!',
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.url
  });
});

app.get('/api/debug', (req, res) => {
  res.json({ 
    message: 'API debug endpoint working!',
    timestamp: new Date().toISOString(),
    path: req.path
  });
});

app.get('/api/health-simple', (req, res) => {
  res.json({ 
    status: 'healthy (simple)',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});
// ================= END DEBUG ROUTES =================

// Import and mount routers - CORRECTED: No duplicate imports
console.log('Loading routers...');

// Helper function to create fallback router
const createFallbackRouter = (routerName) => {
  const router = express.Router();
  router.post('/analyze', (req, res) => {
    res.status(503).json({ 
      error: `${routerName} service temporarily unavailable`,
      message: 'This router failed to load properly'
    });
  });
  return router;
};

// Load each router with error handling
try {
  const networkRouter = require('./scripts/networkAI');
  app.use('/api/network', networkRouter);
  console.log('✓ Network router loaded and mounted');
} catch (error) {
  console.error('✗ Failed to load network router:', error.message);
  app.use('/api/network', createFallbackRouter('Network'));
}

try {
  const endpointRouter = require('./scripts/endpointAI');
  app.use('/api/endpoint', endpointRouter);
  console.log('✓ Endpoint router loaded and mounted');
} catch (error) {
  console.error('✗ Failed to load endpoint router:', error.message);
  app.use('/api/endpoint', createFallbackRouter('Endpoint'));
}

try {
  const appRouter = require('./scripts/appAI');
  app.use('/api/app', appRouter);
  console.log('✓ App router loaded and mounted');
} catch (error) {
  console.error('✗ Failed to load app router:', error.message);
  app.use('/api/app', createFallbackRouter('App'));
}

try {
  const threatIntelRouter = require('./scripts/threatIntelAI');
  app.use('/api/threat-intel', threatIntelRouter);
  console.log('✓ Threat Intel router loaded and mounted');
} catch (error) {
  console.error('✗ Failed to load threat intel router:', error.message);
  app.use('/api/threat-intel', createFallbackRouter('Threat Intel'));
}

// Root endpoint
app.get('/', (req, res) => {
  res.send('SOC AI Agent is running');
});

// Health check endpoint - FIXED: Handle Redis errors
app.get('/api/health', async (req, res) => {
  try {
    const redisStatus = await require('./scripts/unknownAI').ping();
    res.json({ 
      status: 'healthy',
      redis: redisStatus,
      uptime: process.uptime(),
      services: ['network', 'endpoint', 'app', 'threat-intel'],
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.json({ 
      status: 'degraded',
      redis: 'unavailable',
      error: error.message,
      uptime: process.uptime(),
      services: ['network', 'endpoint', 'app', 'threat-intel'],
      timestamp: new Date().toISOString()
    });
  }
});

app.get('/test', (req, res) => {
  res.json({ message: 'Basic test route working', timestamp: new Date().toISOString() });
});

app.get('/api/simple', (req, res) => {
  res.json({ message: 'Simple API route working', timestamp: new Date().toISOString() });
});

app.post('/api/echo', (req, res) => {
  res.json({ 
    message: 'Echo endpoint', 
    received: req.body,
    timestamp: new Date().toISOString() 
  });
});

// Error handling middleware (MUST BE LAST)
app.use((err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] Error:`, err.stack);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: err.message,
    path: req.path
  });
});

// 404 handler for undefined routes
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found',
    requested_url: req.originalUrl,
    available_endpoints: [
      '/debug',
      '/api/debug', 
      '/api/health-simple',
      '/api/health',
      '/api/network/analyze',
      '/api/endpoint/analyze',
      '/api/app/analyze',
      '/api/threat-intel'
    ]
  });
});

// Create HTTP server
const PORT = process.env.PORT || 3000;
const server = http.createServer(app);

// Start server
server.listen(PORT, '0.0.0.0', () => {
  console.log(`\nSOC AI Agent running on port ${PORT}`);
  console.log('Available endpoints:');
  console.log('- GET  /debug          - Basic debug endpoint');
  console.log('- GET  /api/debug      - API debug endpoint');
  console.log('- GET  /api/health-simple - Simple health check');
  console.log('- GET  /api/health     - Full health check');
  console.log('- POST /api/network/analyze   - Network traffic analysis');
  console.log('- POST /api/endpoint/analyze  - Endpoint event analysis');
  console.log('- POST /api/app/analyze       - Rogue AP analysis');
  console.log('- POST /api/threat-intel      - Threat intelligence correlation');
  console.log('\nTest URLs:');
  console.log(`http://localhost:${PORT}/debug`);
  console.log(`http://localhost:${PORT}/api/debug`);
  console.log(`http://localhost:${PORT}/api/health-simple`);
  console.log(`http://localhost:${PORT}/api/health\n`);
});

// Server error handling
server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use.`);
  } else {
    console.error('Server error:', error);
  }
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    require('./scripts/unknownAI').disconnect();
    process.exit(0);
  });
});