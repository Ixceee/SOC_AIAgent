const express = require('express');
const router = express.Router();
const axios = require('axios');

/**
 * POST /api/app/analyze
 * @description Analyze rogue AP events using Claude AI
 * @body {Object} alert - The alert object containing original log data
 */
router.post('/analyze', async (req, res) => {
  try {
    const alert = req.body;
    const log = alert.original || alert;

    // Validate required fields
    if (!log.bssid || !log.ssid) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['original.bssid', 'original.ssid']
      });
    }

    // Build the API request configuration (your original logic)
    const requestConfig = {
      method: "POST",
      url: "https://api.anthropic.com/v1/messages",
      headers: {
        "x-api-key": process.env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json"
      },
      data: {  // Using 'data' instead of 'body' for axios
        model: "claude-3-sonnet-20240229",
        max_tokens: 1000,
        messages: [{
          role: "user",
          content: `Analyze rogue AP event:
          - AP: ${log.bssid} (${log.ssid}) 
          - Signal: ${log.signal}dBm 
          - Vendor: ${log.manuf}
          - Detection: ${log.sndetected}
          
          Provide JSON analysis:
          {
            "threat_level": "high|medium|low",
            "ap_details": {
              "bssid": string,
              "ssid": string,
              "vendor": string
            },
            "recommended_actions": string[],
            "nearby_devices_at_risk": number
          }`
        }],
        temperature: 0.2,
        response_format: { type: "json_object" }
      }
    };

    // Make the API call
    const response = await axios(requestConfig);
    
    // Return the analysis results
    res.json({
      status: 'success',
      data: response.data,
      metadata: {
        analyzedAt: new Date().toISOString(),
        alertId: alert.id || null
      }
    });

  } catch (error) {
    console.error('Analysis failed:', error);
    
    // Handle different error scenarios
    const statusCode = error.response?.status || 500;
    const errorMessage = error.response?.data?.error?.message || error.message;
    
    res.status(statusCode).json({
      status: 'error',
      message: errorMessage,
      details: statusCode === 500 ? undefined : error.response?.data
    });
  }
});

module.exports = router;