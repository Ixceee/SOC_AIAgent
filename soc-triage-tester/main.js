const { app, BrowserWindow } = require('electron');
const path = require('path');
const express = require('express');

// Express Server Setup
const apiServer = express();
const PORT = 3001; // Different from Electron's port

// Middleware
apiServer.use(require('cors')());
apiServer.use(require('helmet')());
apiServer.use(express.json());

// Import Routers
const alertRouter = require('./routes/alertRoutes');
const networkRouter = require('./routes/networkRoutes');
const endpointRouter = require('./routes/endpointRoutes');

// Mount Routers
apiServer.use('/api/alerts', alertRouter);
apiServer.use('/api/network', networkRouter);
apiServer.use('/api/endpoint', endpointRouter);

// Start Express Server
apiServer.listen(PORT, () => {
  console.log(`API Server running on http://localhost:${PORT}`);
});

// Electron Window Setup
function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      enableRemoteModule: true
    }
  });

  // Load your frontend
  win.loadFile('renderer/index.html');
  
  // Open DevTools in development
  if (process.env.NODE_ENV === 'development') {
    win.webContents.openDevTools();
  }
}

app.whenReady().then(createWindow);