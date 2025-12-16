const fs = require('fs');
const path = require('path');

console.log('🔍 Checking router files...\n');

const filesToCheck = [
    './scripts/threatIntelAI.js',
    './scripts/AppAI.js', 
    './scripts/EndpointAI.js'
];

filesToCheck.forEach(filePath => {
    const fullPath = path.resolve(filePath);
    console.log(`📁 Checking: ${filePath}`);
    
    if (fs.existsSync(fullPath)) {
        console.log('   ✅ File exists');
        
        try {
            const stats = fs.statSync(fullPath);
            console.log(`   📊 Size: ${stats.size} bytes`);
            
            // Try to require the file
            try {
                const module = require(fullPath);
                console.log('   ✅ Module loads successfully');
                console.log(`   🔧 Type: ${typeof module}`);
                if (typeof module === 'function') {
                    console.log('   🛣️  Is Express Router: Yes');
                }
            } catch (requireError) {
                console.log('   ❌ Module load failed:', requireError.message);
            }
        } catch (error) {
            console.log('   ❌ Cannot read file stats:', error.message);
        }
    } else {
        console.log('   ❌ File does not exist');
    }
    console.log('');
});

console.log('📋 Current directory:', __dirname);
console.log('📂 Files in scripts directory:');
try {
    const scriptsDir = path.join(__dirname, 'scripts');
    if (fs.existsSync(scriptsDir)) {
        const files = fs.readdirSync(scriptsDir);
        files.forEach(file => {
            console.log(`   - ${file}`);
        });
    } else {
        console.log('   ❌ scripts directory does not exist');
    }
} catch (error) {
    console.log('   ❌ Error reading scripts directory:', error.message);
}