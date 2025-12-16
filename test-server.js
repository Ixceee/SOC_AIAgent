const express = require('express');
const http = require('http');
const app = express();

// Use a DIFFERENT PORT than 11434 (since Ollama is using it)
const PORT = 3000; // Changed from 11434 to 3000

// ========== CRITICAL: PUT ROUTES BEFORE STATIC FILES ==========

// Basic request logging FIRST
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Add JSON parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

// Add a POST endpoint for testing
app.post('/api/echo', (req, res) => {
  res.json({ 
    message: 'Echo endpoint working!',
    received: req.body,
    timestamp: new Date().toISOString() 
  });
});

// ========== STATIC FILES LAST ==========
app.use(express.static('public')); // This should be AFTER all routes

// ========== ERROR HANDLING ==========
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found', 
    url: req.originalUrl,
    available_endpoints: ['/', '/test', '/api/test', '/api/health', '/api/echo']
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
  console.log(`http://localhost:${PORT}/api/health`);
  console.log(`\nTest POST with:`);
  console.log(`Invoke-RestMethod -Uri "http://localhost:${PORT}/api/echo" -Method Post -ContentType "application/json" -Body '{"test":"data"}'`);
});

server.on('error', (error) => {
  console.error('❌ Server error:', error.message);
  if (error.code === 'EADDRINUSE') {
    console.log(`Port ${PORT} is already in use. Trying port 3001...`);
    // Auto-retry with different port
    server.listen(3001, '127.0.0.1');
  } else {
    process.exit(1);
  }
});