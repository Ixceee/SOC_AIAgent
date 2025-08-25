const net = require('net');
const portsToTest = [3000, 3001, 8080, 8000, 8001, 5000, 5001, 3443, 8443, 11435, 11436];

function checkPort(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    
    server.once('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        resolve({ port, available: false });
      } else {
        resolve({ port, available: false, error: err.code });
      }
    });
    
    server.once('listening', () => {
      server.close();
      resolve({ port, available: true });
    });
    
    server.listen(port, '127.0.0.1');
  });
}

async function findAvailablePort() {
  console.log('Checking available ports...\n');
  
  for (const port of portsToTest) {
    const result = await checkPort(port);
    const status = result.available ? '✅ AVAILABLE' : '❌ BLOCKED/IN USE';
    console.log(`Port ${port}: ${status}`);
    
    if (result.available) {
      console.log(`\n🎉 Use port: ${port}`);
      return port;
    }
  }
  
  console.log('\n❌ No common ports available. Trying random ports...');
  
  // Try random ports between 1024-65535
  for (let i = 0; i < 10; i++) {
    const randomPort = Math.floor(Math.random() * (65535 - 1024)) + 1024;
    const result = await checkPort(randomPort);
    if (result.available) {
      console.log(`🎉 Found available port: ${randomPort}`);
      return randomPort;
    }
  }
  
  console.log('❌ Could not find any available ports');
  return null;
}

findAvailablePort().then(port => {
  if (port) {
    console.log(`\nUpdate your server.js with:`);
    console.log(`const PORT = process.env.PORT || ${port};`);
  }
});