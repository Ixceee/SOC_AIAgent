const express = require('express');
const router = express.Router();
const axios = require('axios');

// Constants - OPTIMIZED FOR 24GB RAM
const OLLAMA_BASE = process.env.OLLAMA_HOST || 'http://ollama:11434';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || "llama3.1:8b-instruct-q4_K_M";
const OLLAMA_TIMEOUT = 45000; // Increased timeout for better analysis

/**
 * POST /api/endpoint/analyze
 * @description Analyze endpoint/VPN events using Ollama
 */
router.post('/analyze', async (req, res) => {
  try {
    const alert = req.body;
    const log = alert.original || alert;
    
    // Validation
    if (log.subtype === "vpn" && !log.action) {
      return res.status(400).json({
        error: 'Missing required fields for VPN analysis',
        required: ['original.action', 'original.remip']
      });
    }

    // Build optimized analysis prompt
    let analysisPrompt = '';
    if (log.subtype === "vpn") {
      analysisPrompt = `Analyze this VPN security event and provide JSON response with severity, issues, and actions:
      Type: ${log.tunneltype || 'IPsec'}
      Action: ${log.action}
      Remote IP: ${log.remip}
      Status: ${log.status}
      Reason: ${log.reason || 'N/A'}
      User: ${log.user || 'N/A'}
      Message: ${log.msg || 'N/A'}`;
    } else {
      analysisPrompt = `Analyze this endpoint security event and provide JSON response:
      ${JSON.stringify(log, null, 2)}`;
    }

    // Ollama API request with optimized parameters
    const response = await axios.post(`${OLLAMA_BASE}/api/generate`, {
      model: OLLAMA_MODEL,
      prompt: analysisPrompt,
      format: "json",
      options: { 
        temperature: 0.1,           // Lower temp for more consistent security analysis
        top_p: 0.9,
        top_k: 40,
        num_predict: 1024,          // Enough for detailed analysis
        repeat_penalty: 1.1
      },
      stream: false
    }, {
      headers: { 
        "Content-Type": "application/json",
        "X-SOC-Request-ID": req.id 
      },
      timeout: OLLAMA_TIMEOUT
    });

    // Parse and enhance the response
    let analysisResult;
    try {
      analysisResult = typeof response.data.response === 'string' 
        ? JSON.parse(response.data.response) 
        : response.data.response;
    } catch (parseError) {
      console.warn('JSON parse failed, using raw response:', parseError);
      analysisResult = { raw_response: response.data.response };
    }

    res.json({
      status: 'success',
      analysis: analysisResult,
      metadata: {
        analyzedAt: new Date().toISOString(),
        model: OLLAMA_MODEL,
        alertType: log.subtype || 'endpoint',
        processingTime: response.data.total_duration ? 
          (response.data.total_duration / 1000000000).toFixed(2) + 's' : 'N/A'
      }
    });

  } catch (error) {
    console.error('Endpoint analysis failed:', error.message);
    
    // Enhanced error handling
    const statusCode = error.response?.status || 500;
    const errorMessage = error.response?.data?.error || error.message;
    
    res.status(statusCode).json({
      status: 'error',
      message: errorMessage,
      suggestion: statusCode === 404 ? 'Check if Ollama model is downloaded: ollama pull ' + OLLAMA_MODEL : null,
      model: OLLAMA_MODEL
    });
  }
});

module.exports = router;