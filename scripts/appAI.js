const express = require('express');
const router = express.Router();
const axios = require('axios');

// Constants - Using local Ollama
const OLLAMA_HOST = process.env.OLLAMA_HOST || 'http://localhost:11434';
const OLLAMA_MODEL = process.env.APP_AI_MODEL || "phi3:mini";

/**
 * POST /api/app/analyze
 * @description Analyze rogue AP events using local Ollama
 */
router.post('/analyze', async (req, res) => {
  try {
    const alert = req.body;
    const log = alert.original || alert;

    // Validation
    if (!log.bssid || !log.ssid) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['bssid', 'ssid']
      });
    }

    // Build specialized prompt for wireless security analysis
    const analysisPrompt = `As a wireless security expert, analyze this rogue AP event:

BSSID: ${log.bssid}
SSID: ${log.ssid}
Signal Strength: ${log.rssi || 'N/A'} dBm
Channel: ${log.channel || 'N/A'}
Security: ${log.security || 'Unknown'}
${log.event_type ? `Event Type: ${log.event_type}` : ''}

Analyze for: rogue access point, evil twin attack, misconfiguration, 
enterprise policy violation, or legitimate business AP.

Respond with JSON only:
{
  "threat_level": "critical|high|medium|low|benign",
  "ap_type": "rogue|evil_twin|legitimate|misconfigured|unknown",
  "confidence": 0.0-1.0,
  "key_findings": ["finding1", "finding2"],
  "immediate_actions": ["action1", "action2"],
  "investigation_steps": ["step1", "step2"]
}`;

    // Ollama API request
    const response = await axios.post(`${OLLAMA_HOST}/api/generate`, {
      model: OLLAMA_MODEL,
      prompt: analysisPrompt,
      stream: false,
      options: {
        temperature: 0.1,
        top_p: 0.9,
        num_predict: 768
      }
    }, {
      timeout: 30000
    });

    // Parse the JSON response from Ollama
    const analysisResult = JSON.parse(response.data.response);

    res.json({
      status: 'success',
      analysis: analysisResult,
      metadata: {
        analyzedAt: new Date().toISOString(),
        model: OLLAMA_MODEL,
        processingTime: `${(response.data.total_duration / 1000000000).toFixed(2)}s`
      }
    });

  } catch (error) {
    console.error('App analysis failed:', error.message);
    const statusCode = error.response?.status || 500;
    
    res.status(statusCode).json({
      status: 'error',
      message: error.response?.data?.error || error.message,
      model: OLLAMA_MODEL,
      suggestion: statusCode === 404 ? `Check if Ollama model is downloaded: ollama pull ${OLLAMA_MODEL}` : null
    });
  }
});

module.exports = router;