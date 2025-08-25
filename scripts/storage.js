const fs = require('fs');
const path = require('path');

// Configuration
const STORAGE_DIR = path.join(__dirname, '../storage');
const ALERTS_FILE = path.join(STORAGE_DIR, 'alerts.json');
const CONFIG_FILE = path.join(STORAGE_DIR, 'config.json');

// Initialize storage
if (!fs.existsSync(STORAGE_DIR)) {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
  fs.writeFileSync(ALERTS_FILE, '[]');
  fs.writeFileSync(CONFIG_FILE, '{}');
}

// Alert storage
const alerts = {
  save: (alert) => {
    const allAlerts = alerts.getAll();
    allAlerts.push({
      ...alert,
      id: alert.id || Date.now().toString(),
      timestamp: new Date().toISOString()
    });
    fs.writeFileSync(ALERTS_FILE, JSON.stringify(allAlerts, null, 2));
    return true;
  },

  getAll: () => {
    try {
      return JSON.parse(fs.readFileSync(ALERTS_FILE));
    } catch (err) {
      console.error('Error reading alerts:', err);
      return [];
    }
  },

  getById: (id) => {
    return alerts.getAll().find(a => a.id === id);
  },

  updateStatus: (id, status) => {
    const allAlerts = alerts.getAll();
    const index = allAlerts.findIndex(a => a.id === id);
    if (index !== -1) {
      allAlerts[index].status = status;
      fs.writeFileSync(ALERTS_FILE, JSON.stringify(allAlerts, null, 2));
      return true;
    }
    return false;
  }
};

// Config storage
const config = {
  get: (key) => {
    try {
      const data = JSON.parse(fs.readFileSync(CONFIG_FILE));
      return key ? data[key] : data;
    } catch (err) {
      return key ? null : {};
    }
  },

  set: (key, value) => {
    const data = config.get();
    data[key] = value;
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(data, null, 2));
    return true;
  }
};

module.exports = {
  alerts,
  config,
  clearStorage: () => {
    fs.writeFileSync(ALERTS_FILE, '[]');
    fs.writeFileSync(CONFIG_FILE, '{}');
    return true;
  }
};