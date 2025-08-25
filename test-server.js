const express = require('express');
const http = require('http');
const app = express();
const PORT = 11434;

// ========== CRITICAL: PUT ROUTES BEFORE STATIC FILES ==========

// Basic request logging FIRST
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ========== DEFINE ALL ROUTES FIRST ==========
app.get('/', (req, res) => {
  res.json({ 
    message: 'Root endpoint working!', 
    timestamp: new Date().toISOString(),
    port: PORT
  });
});

app.get('/test', (req, res) => {
  res.json({ 
    message: 'Test endpoint working!', 
    timestamp: new Date().toISOString() 
  });
});

app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'API test endpoint working!', 
    timestamp: new Date().toISOString() 
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    port: PORT
  });
});

// ========== STATIC FILES LAST ==========
app.use(express.static('public')); // This should be AFTER all routes

// ========== ERROR HANDLING ==========
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found', 
    url: req.originalUrl,
    available_endpoints: ['/', '/test', '/api/test', '/api/health']
  });
});

// Create server
const server = http.createServer(app);

server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n✅ Test server running on http://localhost:${PORT}`);
  console.log('Test these URLs:');
  console.log(`http://localhost:${PORT}/`);
  console.log(`http://localhost:${PORT}/test`);
  console.log(`http://localhost:${PORT}/api/test`);
  console.log(`http://localhost:${PORT}/api/health\n`);
});

server.on('error', (error) => {
  console.error('❌ Server error:', error.message);
  process.exit(1);
});