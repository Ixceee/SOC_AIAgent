#!/usr/bin/env node
require('dotenv').config();
const path = require('path');
const axios = require('axios');

// Corrected module imports
const classifyAlert = require('../scripts/classifyAlert');
const { alerts } = require('../scripts/storage'); // Using the exported alerts object
const threatIntelAI = require('../scripts/threatIntelAI');

// Path to test data
const testDataPath = path.join(__dirname, '../test-data/logs.json');

// Analyzer loader with error handling
function getAnalyzer(alertType) {
  try {
    return require(`../scripts/${alertType}AI`);
  } catch (error) {
    console.error(`Failed to load analyzer for type: ${alertType}`);
    return null;
  }
}

async function processSingleAlert(log, index, total) {
  try {
    // 1. Classify the alert
    const classified = classifyAlert(log);
    
    // 2. Store the raw alert
    await alerts.save(classified);
    
    // 3. Get appropriate analyzer
    const analyzer = getAnalyzer(classified.type);
    if (!analyzer) {
      throw new Error(`No analyzer available for type: ${classified.type}`);
    }
    
    // 4. Get analysis configuration
    const analysisRequest = analyzer(classified);
    
    // 5. Execute analysis
    const analysisResponse = await axios(analysisRequest);
    const analysisResult = analysisResponse.data;
    
    // 6. Add threat intel if high severity
    if (classified.severity >= 4) {
      try {
        const intelResponse = await axios(threatIntelAI(classified));
        analysisResult.threat_intel = intelResponse.data;
      } catch (intelError) {
        console.warn(`Threat intel failed: ${intelError.message}`);
        analysisResult.threat_intel = { error: "Threat intel lookup failed" };
      }
    }
    
    // 7. Prepare final output
    const finalAnalysis = {
      ...classified,
      analysis: analysisResult,
      timestamp: new Date().toISOString(),
      status: 'analyzed'
    };
    
    // 8. Save complete analysis
    await alerts.save(finalAnalysis);
    
    console.log(`[${index + 1}/${total}] ${classified.type.toUpperCase()} Alert Processed`);
    console.log({
      id: finalAnalysis.id,
      type: finalAnalysis.type,
      severity: finalAnalysis.severity,
      action: finalAnalysis.analysis?.recommended_action || 'review'
    });
    
    return finalAnalysis;
  } catch (error) {
    console.error(`Error processing alert ${index + 1}:`, error.message);
    await alerts.save({
      ...log,
      status: 'failed',
      error: error.message,
      timestamp: new Date().toISOString()
    });
    return null;
  }
}

async function main() {
  try {
    const logs = require(testDataPath);
    console.log(`Processing ${logs.length} alerts...`);
    
    // Process alerts sequentially
    for (const [index, log] of logs.entries()) {
      await processSingleAlert(log, index, logs.length);
    }
    
    console.log('Analysis complete!');
    process.exit(0);
  } catch (error) {
    console.error('Fatal error:', error.message);
    process.exit(1);
  }
}

main();