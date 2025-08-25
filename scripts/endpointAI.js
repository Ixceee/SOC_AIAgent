const express = require('express');
const router = express.Router();
const axios = require('axios');

// Constants
const OLLAMA_BASE = process.env.OLLAMA_HOST || 'http://ollama:11434';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || "llama3:8b-instruct-q4_0";

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

    // Build analysis prompt
    let analysisPrompt = '';
    if (log.subtype === "vpn") {
      analysisPrompt = `VPN ${log.tunneltype || 'IPsec'} event: ${log.action}. 
      Remote IP: ${log.remip}, Status: ${log.status}, Reason: ${log.reason || 'N/A'}`;
    } else {
      analysisPrompt = JSON.stringify(log);
    }

    // Ollama API request
    const response = await axios.post(`${OLLAMA_BASE}/api/generate`, {
      model: OLLAMA_MODEL,
      prompt: `[INST] <<SYS>>Analyze security event and return JSON: {
        "severity": "critical|high|medium|low",
        "issues": string[],
        "action_required": boolean
      }<</SYS>>${analysisPrompt}[/INST]`,
      format: "json",
      options: { temperature: 0.3 }
    }, {
      headers: { 
        "Content-Type": "application/json",
        "X-SOC-Request-ID": req.id 
      },
      timeout: 30000
    });

    res.json({
      status: 'success',
      data: response.data,
      metadata: {
        analyzedAt: new Date().toISOString(),
        model: OLLAMA_MODEL,
        alertType: log.subtype || 'endpoint'
      }
    });

  } catch (error) {
    console.error('Endpoint analysis failed:', error);
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({
      status: 'error',
      message: error.response?.data?.error || error.message,
      ...(statusCode !== 500 && { request: error.config?.data })
    });
  }
});

module.exports = router;