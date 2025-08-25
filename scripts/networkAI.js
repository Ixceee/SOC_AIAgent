const express = require('express');
const router = express.Router();
const axios = require('axios');

// Constants
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-4-turbo-preview";

/**
 * POST /api/network/analyze
 * @description Analyze network traffic/wireless events
 */
router.post('/analyze', async (req, res) => {
    try {
        const alert = req.body;
        const log = alert.original || alert;

        // Validation
        if (!log.type || !(log.type === 'traffic' || log.subtype === 'wireless')) {
            return res.status(400).json({
                error: 'Invalid network alert type',
                valid_types: ['traffic', 'wireless']
            });
        }

        // Build analysis context
        let analysisContext = "";
        if (log.type === "traffic") {
            analysisContext = `Traffic between ${log.srcip}:${log.srcport} → ${log.dstip}:${log.dstport}`;
        } else {
            analysisContext = `Wireless event: ${log.bssid} (${log.ssid})`;
        }

        // OpenAI API request
        const response = await axios.post('https://api.openai.com/v1/chat/completions', {
            model: OPENAI_MODEL,
            messages: [{
                role: "system",
                content: "Analyze network event and return JSON: {risk_score: number, threat_type: string, recommended_actions: string[]}"
            }, {
                role: "user",
                content: analysisContext
            }],
            response_format: { type: "json_object" },
            temperature: 0.2
        }, {
            headers: {
                "Authorization": `Bearer ${OPENAI_API_KEY}`,
                "Content-Type": "application/json"
            },
            timeout: 15000
        });

        res.json({
            status: 'success',
            data: response.data.choices[0].message.content,
            metadata: {
                analyzedAt: new Date().toISOString(),
                model: OPENAI_MODEL
            }
        });

    } catch (error) {
        console.error('Network analysis failed:', error);
        const statusCode = error.response?.status || 500;
        res.status(statusCode).json({
            status: 'error',
            message: error.response?.data?.error?.message || error.message,
            ...(statusCode !== 500 && { request: error.config?.data })
        });
    }
});

module.exports = router;