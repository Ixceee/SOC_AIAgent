const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const app = express();

// SSL Certificate Configuration
const sslDir = path.join(__dirname, 'ssl');
const privateKey = fs.readFileSync(path.join(sslDir, 'key.pem'), 'utf8');
const certificate = fs.readFileSync(path.join(sslDir, 'cert.pem'), 'utf8');
const credentials = { 
  key: privateKey, 
  cert: certificate,
  passphrase: '' // Add if your key has a passphrase
};

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Import and mount routers
const networkRouter = require('./scripts/networkAI');
const endpointRouter = require('./scripts/endpointAI');
const threatIntelRouter = require('./scripts/threatIntelAI');

// Route mounting with consistent prefix
app.use('/api/network', networkRouter);
app.use('/api/endpoint', endpointRouter);
app.use('/api/threat-intel', threatIntelRouter);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    services: ['network', 'endpoint', 'threat-intel'],
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] Error:`, err.stack);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: err.message,
    path: req.path
  });
});

// Create HTTPS server
const PORT = 11434;
const server = https.createServer(credentials, app);

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\nSOC AI Agent running on port ${PORT}`);
  console.log('Available endpoints:');
  console.log(`- POST /api/network   - Network traffic analysis`);
  console.log(`- POST /api/endpoint  - Endpoint event analysis`);
  console.log(`- POST /api/threat-intel - Threat intelligence correlation`);
  console.log(`- GET  /api/health    - Service status check\n`);
  
  // For development, log the full URLs
  console.log('Test URLs:');
  console.log(`https://localhost:${PORT}/api/health`);
  console.log(`https://<your-local-ip>:${PORT}/api/health\n`);
});

// Handle server errors
server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Please check for other running services.`);
  } else {
    console.error('Server error:', error);
  }
  process.exit(1);
});