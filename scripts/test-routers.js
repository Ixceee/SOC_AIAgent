const path = require('path');

console.log('🔍 Testing router loading...');

// Test loading each router
const routers = [
    { name: 'threatIntelAI', path: './scripts/threatIntelAI' },
    { name: 'AppAI', path: './scripts/AppAI' },
    { name: 'EndpointAI', path: './scripts/EndpointAI' }
];

routers.forEach(router => {
    try {
        console.log(`\n📡 Loading ${router.name}...`);
        const loaded = require(router.path);
        console.log(`✅ ${router.name} loaded successfully`);
        console.log(`   Type: ${typeof loaded}`);
        console.log(`   Is Router: ${typeof loaded === 'function' && loaded.name === 'router'}`);
    } catch (error) {
        console.log(`❌ Failed to load ${router.name}: ${error.message}`);
    }
});