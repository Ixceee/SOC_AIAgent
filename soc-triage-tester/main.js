const { app, BrowserWindow, ipcMain } = require('electron');
const axios = require('axios');
require('dotenv').config();

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1000,
    height: 800,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    }
  });

  mainWindow.loadFile('index.html');
}

// API Communication
ipcMain.handle('submit-alert', async (_, alert) => {
  try {
    const response = await axios.post(
      process.env.API_URL || 'http://localhost:3000/api/analyze',
      alert
    );
    return response.data;
  } catch (error) {
    return { error: error.message };
  }
});

app.whenReady().then(createWindow);