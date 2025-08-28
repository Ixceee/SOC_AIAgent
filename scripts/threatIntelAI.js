const axios = require('axios');
const express = require('express');
const router = express.Router();

// Default threat intelligence data (can be expanded)
const DEFAULT_THREAT_INTEL = {
  malicious_ips: [
    '192.168.1.100',
    '10.0.0.666',
    '172.16.0.13'
  ],
  malicious_domains: [
    'evil-domain.com',
    'malware-distribution.net',
    'phishing-site.org'
  ],
  malicious_hashes: [
    'abc123def456',
    'deadbeefcafe',
    'malwarehash123'
  ]
};

class ThreatIntelAI {
  constructor() {
    this.knownThreats = DEFAULT_THREAT_INTEL;
  }

  async analyzeThreat(req, res) {
    try {
      const alertData = req.body;
      
      if (!alertData || Object.keys(alertData).length === 0) {
        return res.status(400).json({ error: 'No alert data provided' });
      }

      console.log('ThreatIntel analyzing:', alertData['Event Type'] || 'Unknown alert');

      // Extract IOCs from the alert
      const iocs = this.extractIOCs(alertData);
      
      // Check against known threats
      const localAnalysis = this.analyzeLocally(iocs);
      
      // If we have OpenAI API key, use AI analysis
      let aiAnalysis = null;
      if (process.env.OPENAI_API_KEY) {
        aiAnalysis = await this.analyzeWithAI(iocs);
      }

      // Combine results
      const result = {
        verdict: localAnalysis.verdict || 'unknown',
        confidence: localAnalysis.confidence || 0.5,
        matched_iocs: localAnalysis.matched_iocs || [],
        local_analysis: localAnalysis,
        ai_analysis: aiAnalysis,
        extracted_iocs: iocs,
        timestamp: new Date().toISOString()
      };

      res.json(result);

    } catch (error) {
      console.error('Threat intelligence analysis error:', error);
      res.status(500).json({ 
        error: 'Failed to analyze threat',
        message: error.message 
      });
    }
  }

  extractIOCs(alertData) {
    const iocs = {
      ips: new Set(),
      domains: new Set(),
      hashes: new Set(),
      users: new Set(),
      processes: new Set()
    };

    // Extract from common fields
    const ipFields = ['srcip', 'dstip', 'remip', 'locip', 'ip', 'source_ip', 'destination_ip'];
    const domainFields = ['domain', 'hostname', 'url', 'fqdn'];
    const hashFields = ['hash', 'file_hash', 'process_hash', 'md5', 'sha1', 'sha256'];
    const userFields = ['user', 'username', 'account'];
    const processFields = ['process', 'process_name', 'image_path'];

    // Helper function to add values to sets
    const addToSet = (set, value) => {
      if (value && typeof value === 'string') {
        set.add(value.toLowerCase());
      }
    };

    // Check all fields in alert data
    for (const [key, value] of Object.entries(alertData)) {
      const keyLower = key.toLowerCase();
      
      if (ipFields.some(field => keyLower.includes(field))) {
        addToSet(iocs.ips, value);
      }
      else if (domainFields.some(field => keyLower.includes(field))) {
        addToSet(iocs.domains, value);
      }
      else if (hashFields.some(field => keyLower.includes(field))) {
        addToSet(iocs.hashes, value);
      }
      else if (userFields.some(field => keyLower.includes(field))) {
        addToSet(iocs.users, value);
      }
      else if (processFields.some(field => keyLower.includes(field))) {
        addToSet(iocs.processes, value);
      }
    }

    // Convert sets to arrays
    return {
      ips: Array.from(iocs.ips),
      domains: Array.from(iocs.domains),
      hashes: Array.from(iocs.hashes),
      users: Array.from(iocs.users),
      processes: Array.from(iocs.processes)
    };
  }

  analyzeLocally(iocs) {
    const matched_iocs = [];
    let confidence = 0;
    let verdict = 'benign';

    // Check IPs against known threats
    for (const ip of iocs.ips) {
      if (this.knownThreats.malicious_ips.includes(ip)) {
        matched_iocs.push(`malicious_ip:${ip}`);
        confidence += 0.3;
      }
    }

    // Check domains against known threats
    for (const domain of iocs.domains) {
      if (this.knownThreats.malicious_domains.includes(domain)) {
        matched_iocs.push(`malicious_domain:${domain}`);
        confidence += 0.4;
      }
    }

    // Check hashes against known threats
    for (const hash of iocs.hashes) {
      if (this.knownThreats.malicious_hashes.includes(hash)) {
        matched_iocs.push(`malicious_hash:${hash}`);
        confidence += 0.8;
      }
    }

    // Determine verdict based on confidence
    if (confidence > 0.7) {
      verdict = 'malicious';
    } else if (confidence > 0.3) {
      verdict = 'suspicious';
    } else if (matched_iocs.length > 0) {
      verdict = 'suspicious_low_confidence';
    }

    return {
      verdict,
      confidence: Math.min(confidence, 1.0),
      matched_iocs,
      total_iocs_checked: iocs.ips.length + iocs.domains.length + iocs.hashes.length
    };
  }

  async analyzeWithAI(iocs) {
    try {
      // Only call OpenAI if we have IOCs to analyze
      const hasIOCs = iocs.ips.length > 0 || iocs.domains.length > 0 || iocs.hashes.length > 0;
      if (!hasIOCs) {
        return { verdict: 'no_iocs_to_analyze' };
      }

      const response = await axios.post('https://api.openai.com/v1/chat/completions', {
        model: process.env.OPENAI_MODEL || "gpt-4-turbo-preview",
        messages: [
          {
            role: "system",
            content: `You are a cybersecurity threat intelligence analyst. Analyze these IOCs and provide a JSON response with: 
            {
              verdict: "malicious|suspicious|benign|unknown",
              confidence: 0.0-1.0,
              matched_iocs: string[],
              reasoning: string,
              recommendations: string[]
            }
            
            Known threat patterns to consider:
            IPs: ${JSON.stringify(this.knownThreats.malicious_ips)}
            Domains: ${JSON.stringify(this.knownThreats.malicious_domains)}
            Hashes: ${JSON.stringify(this.knownThreats.malicious_hashes)}`
          },
          {
            role: "user",
            content: `Analyze these IOCs for malicious activity:\n${JSON.stringify(iocs, null, 2)}`
          }
        ],
        response_format: { type: "json_object" },
        max_tokens: 1000,
        temperature: 0.1
      }, {
        headers: {
          "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`,
          "Content-Type": "application/json"
        },
        timeout: 30000
      });

      return JSON.parse(response.data.choices[0].message.content);

    } catch (error) {
      console.error('OpenAI analysis failed:', error.message);
      return {
        verdict: "analysis_failed",
        error: error.message,
        confidence: 0
      };
    }
  }

  // Method to add new threats
  addThreats(newThreats) {
    if (newThreats.ips) {
      this.knownThreats.malicious_ips = [...new Set([...this.knownThreats.malicious_ips, ...newThreats.ips])];
    }
    if (newThreats.domains) {
      this.knownThreats.malicious_domains = [...new Set([...this.knownThreats.malicious_domains, ...newThreats.domains])];
    }
    if (newThreats.hashes) {
      this.knownThreats.malicious_hashes = [...new Set([...this.knownThreats.malicious_hashes, ...newThreats.hashes])];
    }
  }

  // Method to get current threat database
  getThreatDatabase() {
    return this.knownThreats;
  }
}

// Create instance and set up routes
const threatIntel = new ThreatIntelAI();

// Main analysis endpoint
router.post('/analyze', threatIntel.analyzeThreat.bind(threatIntel));

// Additional endpoints for threat management
router.post('/threats', (req, res) => {
  try {
    const { threats } = req.body;
    threatIntel.addThreats(threats);
    res.json({ 
      success: true, 
      message: 'Threats added successfully',
      current_threats: threatIntel.getThreatDatabase()
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/threats', (req, res) => {
  res.json(threatIntel.getThreatDatabase());
});

router.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    has_openai: !!process.env.OPENAI_API_KEY,
    threat_counts: {
      ips: threatIntel.knownThreats.malicious_ips.length,
      domains: threatIntel.knownThreats.malicious_domains.length,
      hashes: threatIntel.knownThreats.malicious_hashes.length
    }
  });
});

module.exports = router;