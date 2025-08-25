require('dotenv').config();
const express = require('express');
const http = require('http'); // Changed from https to http
const fs = require('fs');
const path = require('path');
const morgan = require('morgan');
const app = express();

// Remove SSL certificate configuration since we're using HTTP
// const sslDir = path.join(__dirname, 'ssl');
// try {
//   const privateKey = fs.readFileSync(path.join(sslDir, 'key.pem'), 'utf8');
//   const certificate = fs.readFileSync(path.join(sslDir, 'cert.pem'), 'utf8');
//   var credentials = { 
//     key: privateKey, 
//     cert: certificate,
//     passphrase: process.env.SSL_PASSPHRASE || ''
//   };
// } catch (err) {
//   console.error('SSL certificate error:', err);
//   process.exit(1);
// }

// Middleware
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ================= DEBUG ROUTES =================
// Add these right after middleware but before other routes
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

// Test direct health endpoint
app.get('/api/health-simple', (req, res) => {
  res.json({ 
    status: 'healthy (simple)',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});
// ================= END DEBUG ROUTES =================

// Import and mount routers
console.log('Loading routers...');
try {
  const networkRouter = require('./scripts/networkAI');
  console.log('✓ Network router loaded');
} catch (error) {
  console.error('✗ Failed to load network router:', error.message);
}

try {
  const endpointRouter = require('./scripts/endpointAI');
  console.log('✓ Endpoint router loaded');
} catch (error) {
  console.error('✗ Failed to load endpoint router:', error.message);
}

try {
  const appRouter = require('./scripts/appAI');
  console.log('✓ App router loaded');
} catch (error) {
  console.error('✗ Failed to load app router:', error.message);
}

try {
  const threatIntelRouter = require('./scripts/threatIntelAI');
  console.log('✓ Threat Intel router loaded');
} catch (error) {
  console.error('✗ Failed to load threat intel router:', error.message);
}

const networkRouter = require('./scripts/networkAI');
const endpointRouter = require('./scripts/endpointAI');
const appRouter = require('./scripts/appAI');
const threatIntelRouter = require('./scripts/threatIntelAI');

// Route mounting
app.use('/api/network', networkRouter);
app.use('/api/endpoint', endpointRouter);
app.use('/api/app', appRouter);
app.use('/api/threat-intel', threatIntelRouter);

// Root endpoint
app.get('/', (req, res) => {
  res.send('SOC AI Agent is running');
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  const redisStatus = await require('./scripts/unknownAI').ping();
  
  // Set proper headers for browser
  res.setHeader('Content-Type', 'application/json');
  
  res.json({ 
    status: 'healthy',
    redis: redisStatus,
    uptime: process.uptime(),
    services: ['network', 'endpoint', 'app', 'threat-intel'],
    timestamp: new Date().toISOString()
  });
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

// Create HTTP server (instead of HTTPS)
const PORT = process.env.PORT || 3000;
const server = http.createServer(app); // Removed credentials parameter

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