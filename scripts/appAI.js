const express = require('express');
const router = express.Router();
const axios = require('axios');

// Constants
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

/**
 * POST /api/app/analyze
 * @description Analyze rogue AP events
 */
router.post('/analyze', async (req, res) => {
  try {
    const alert = req.body;
    const log = alert.original || alert;

    // Validation
    if (!log.bssid || !log.ssid) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['original.bssid', 'original.ssid']
      });
    }

    // Claude API request
    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model: "claude-3-sonnet-20240229",
      max_tokens: 1000,
      messages: [{
        role: "user",
        content: `Analyze rogue AP event (${log.bssid}) and return JSON: {
          threat_level: string,
          recommended_actions: string[]
        }`
      }],
      response_format: { type: "json_object" }
    }, {
      headers: {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json"
      }
    });

    res.json({
      status: 'success',
      data: response.data,
      metadata: {
        analyzedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('App analysis failed:', error);
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({
      status: 'error',
      message: error.response?.data?.error?.message || error.message
    });
  }
});

module.exports = router;