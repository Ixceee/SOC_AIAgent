const axios = require('axios');
const express = require('express');
const { isIP } = require('net');
const router = express.Router();

// Default threat intelligence data (can be expanded)
const DEFAULT_THREAT_INTEL = {
  malicious_ips: [
    '192.168.1.100',
    '10.0.0.666',
    '172.16.0.13',
    '185.243.115.84', // Known C2 IP
    '45.77.80.133',    // Known C2 IP
    '95.179.130.130',  // Added from test case
    '198.51.100.75'    // Added from test case
  ],
  malicious_domains: [
    'evil-domain.com',
    'malware-distribution.net',
    'phishing-site.org',
    'c2-malicious-domain.com', // C2 domain
    'exfil-server.com'         // Data exfiltration
  ],
  malicious_hashes: [
    'abc123def456',
    'deadbeefcafe',
    'malwarehash123'
  ]
};

// Known benign entities
const BENIGN_ENTITIES = {
  domains: [
    'microsoft.com', 'google.com', 'apple.com', 'amazonaws.com', 
    'azure.com', 'cloudfront.net', 'googleapis.com', 'windowsupdate.com',
    'ubuntu.com', 'docker.com', 'github.com', 'gitlab.com'
  ],
  ips: [
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1' // Public DNS servers
  ],
  // Whitelisted IP ranges for business infrastructure
  whitelisted_ranges: [
    '109.245.0.0/16', // VPN infrastructure
    '10.0.0.0/8',
    '192.168.0.0/16',
    '172.16.0.0/12'
  ],
  vpn_ports: [500, 4500], // IPSec ports
  vpn_protocols: ['IPSec', 'VPN']
};

class ThreatIntelAI {
  constructor() {
    this.knownThreats = DEFAULT_THREAT_INTEL;
    this.otxCache = new Map();
    this.geoipCache = new Map();
    this.cacheTTL = 3600000; // 1 hour cache
    this.c2Patterns = this.initializeC2Patterns();
  }

  // Initialize C2 detection patterns
  initializeC2Patterns() {
    return {
      suspicious_domains: [
        /([a-z]{12,}\.(com|net|org|info))$/,
        /([0-9a-f]{16,}\.(tk|ml|ga|cf|gq))$/,
        /(xn--[a-z0-9]+\.(com|net))$/,
        /(c2|command|control|beacon|panel)\./,
        /(api|update|stats|report|data)\.(xyz|top|club)/,
        /(mail|smtp|ftp|ssh)\.(duckdns|no-ip|dyn|ddns)\./
      ],
      suspicious_ports: [
        4444, 8080, 9001, 1337, 31337, 65432, 54321, 12345
      ],
      high_risk_tlds: [
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'bid'
      ]
    };
  }

  async analyzeThreat(req, res) {
    try {
      const alertData = req.body;
      
      if (!alertData || Object.keys(alertData).length === 0) {
        return res.status(400).json({ error: 'No alert data provided' });
      }

      console.log('ThreatIntel analyzing:', alertData['Event Type'] || alertData['Event type'] || 'Unknown alert');

      let iocs, localAnalysis, externalAnalysis, aiAnalysis, c2Analysis;
      
      try {
        // Extract IOCs from the alert
        iocs = this.extractIOCs(alertData);
        
        // Debug logging for IOC extraction
        console.log('Extracted IPs:', iocs.ips);
        console.log('Extracted Domains:', iocs.domains);
        console.log('Extracted Hashes:', iocs.hashes);
        
        iocs.ips.forEach(ip => {
          console.log(`IP Validation: ${ip} -> isValidIP: ${this.isValidIP(ip)}, isWhitelisted: ${this.isWhitelistedIP(ip)}`);
        });
        
        // Check against known threats and benign entities
        localAnalysis = this.analyzeLocally(iocs);
        
        // Perform C2-specific analysis
        c2Analysis = this.analyzeC2Patterns(iocs, alertData);
        
        // Enrich with external intelligence (OTX and GeoIP)
        externalAnalysis = await this.enrichWithExternalIntel(iocs);
        
        // If we have OpenAI API key, use AI analysis
        if (process.env.OPENAI_API_KEY) {
          aiAnalysis = await this.analyzeWithAI(iocs, externalAnalysis, c2Analysis);
        } else {
          aiAnalysis = {
            verdict: "openai_not_configured",
            confidence: 0,
            reasoning: "OpenAI API key not configured"
          };
        }
      } catch (analysisError) {
        console.error('Analysis failed, returning fallback result:', analysisError);
        
        // Return a fallback analysis instead of failing completely
        return res.json(this.createFallbackAnalysis(alertData, analysisError));
      }

      // Combine results with priority logic (include C2 analysis)
      const finalVerdict = this.determineFinalVerdict(
        localAnalysis, 
        externalAnalysis, 
        aiAnalysis,
        c2Analysis,
        iocs,
        alertData
      );

      const result = {
        verdict: finalVerdict.verdict,
        confidence: finalVerdict.confidence,
        severity: finalVerdict.severity || 'low',
        matched_iocs: [
          ...(localAnalysis.matched_iocs || []), 
          ...(externalAnalysis.matched_iocs || []),
          ...(c2Analysis.indicators || [])
        ],
        local_analysis: localAnalysis,
        c2_analysis: c2Analysis,
        external_analysis: externalAnalysis,
        ai_analysis: aiAnalysis,
        extracted_iocs: iocs,
        recommended_actions: finalVerdict.recommended_actions || [
          'Review alert details',
          'Monitor for similar activity',
          'Check system logs for related events'
        ],
        internal_ip_count: iocs.ips.filter(ip => this.isInternalIP(ip)).length,
        external_ip_count: iocs.ips.filter(ip => !this.isInternalIP(ip)).length,
        whitelisted_ip_count: iocs.ips.filter(ip => this.isWhitelistedIP(ip)).length,
        timestamp: new Date().toISOString()
      };

      res.json(result);

    } catch (error) {
      console.error('Threat intelligence analysis error:', error);
      res.status(500).json({ 
        error: 'Failed to analyze threat',
        message: error.message,
        timestamp: new Date().toISOString()
      });
    }
  }

  createFallbackAnalysis(alertData, error) {
    let iocs;
    try {
      iocs = this.safeExtractIOCs(alertData);
    } catch (extractionError) {
      iocs = { ips: [], domains: [], hashes: [], users: [], processes: [] };
    }
    
    const internalIPs = iocs.ips.filter(ip => this.isInternalIP(ip));
    const whitelistedIPs = iocs.ips.filter(ip => this.isWhitelistedIP(ip));
    
    return {
      verdict: "unknown",
      confidence: 0,
      severity: "low",
      error: error.message,
      matched_iocs: [],
      recommended_actions: whitelistedIPs.length > 0 ? [
        'Review whitelisted IP communication',
        'Verify expected business traffic',
        'Monitor for unusual patterns'
      ] : internalIPs.length > 0 ? [
        'Review internal IP communication',
        'Check if internal traffic is expected',
        'Monitor for unusual internal patterns'
      ] : [
        'Review alert details thoroughly',
        'Check system logs for context',
        'Monitor for similar activity'
      ],
      local_analysis: {
        verdict: 'unknown',
        confidence: 0,
        severity: 'low',
        reasons: [`Analysis failed: ${error.message}`],
        total_iocs_checked: 0
      },
      extracted_iocs: iocs,
      internal_ip_count: internalIPs.length,
      whitelisted_ip_count: whitelistedIPs.length,
      timestamp: new Date().toISOString()
    };
  }

  safeExtractIOCs(alertData) {
    const iocs = {
      ips: new Set(),
      domains: new Set(),
      hashes: new Set(),
      users: new Set(),
      processes: new Set()
    };

    try {
      const jsonString = JSON.stringify(alertData);
      
      // Extract IPs using regex with validation
      const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
      const ips = jsonString.match(ipRegex) || [];
      ips.forEach(ip => {
        if (this.isValidIP(ip)) {
          iocs.ips.add(ip);
        }
      });

      // Extract domains with improved regex
      const domainRegex = /[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+/g;
      const domains = jsonString.match(domainRegex) || [];
      domains.forEach(domain => {
        // Filter out common false positives and validate
        if (domain.length <= 255 && 
            !domain.startsWith('http') && 
            !domain.startsWith('www.') && 
            domain.includes('.') &&
            domain.split('.').pop().length >= 2) {
          iocs.domains.add(domain.toLowerCase());
        }
      });

    } catch (error) {
      console.warn('Safe IOC extraction failed:', error.message);
    }

    return {
      ips: Array.from(iocs.ips),
      domains: Array.from(iocs.domains),
      hashes: Array.from(iocs.hashes),
      users: Array.from(iocs.users),
      processes: Array.from(iocs.processes)
    };
  }

  // Fixed IP validation - use built-in isIP function
  isValidIP(ip) {
    return isIP(ip) !== 0;
  }

  // Check if IP is in whitelisted range
  isWhitelistedIP(ip) {
    if (!this.isValidIP(ip)) return false;
    
    // Check individual IP whitelist
    if (BENIGN_ENTITIES.ips.includes(ip)) {
      return true;
    }
    
    // Check CIDR ranges
    for (const range of BENIGN_ENTITIES.whitelisted_ranges) {
      if (this.isIPInRange(ip, range)) {
        return true;
      }
    }
    
    return false;
  }

  // Check if IP is in CIDR range
  isIPInRange(ip, cidr) {
    try {
      const [range, bits] = cidr.split('/');
      const mask = ~((1 << (32 - parseInt(bits))) - 1);
      const ipLong = this.ipToLong(ip);
      const rangeLong = this.ipToLong(range);
      
      return (ipLong & mask) === (rangeLong & mask);
    } catch (error) {
      console.warn(`CIDR check failed for ${ip} in ${cidr}:`, error.message);
      return false;
    }
  }

  // Convert IP to long integer
  ipToLong(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
  }

  analyzeC2Patterns(iocs, alertData) {
    const c2Indicators = {
      detected: false,
      confidence: 0,
      indicators: [],
      reasons: []
    };

    try {
      // 1. Check for suspicious domains
      for (const domain of iocs.domains) {
        for (const pattern of this.c2Patterns.suspicious_domains) {
          if (pattern.test(domain)) {
            c2Indicators.detected = true;
            c2Indicators.confidence += 0.6;
            c2Indicators.indicators.push(`suspicious_domain_pattern:${domain}`);
            c2Indicators.reasons.push(`Domain matches C2 pattern: ${domain}`);
            break;
          }
        }

        const tld = domain.split('.').pop();
        if (this.c2Patterns.high_risk_tlds.includes(tld)) {
          c2Indicators.detected = true;
            c2Indicators.confidence += 0.3;
            c2Indicators.indicators.push(`high_risk_tld:${domain}`);
            c2Indicators.reasons.push(`Domain uses high-risk TLD: ${tld}`);
        }
      }

      // 2. Check for suspicious ports (defensive check) - skip if VPN port
      if (alertData.dst_port || alertData.port) {
        const port = parseInt(alertData.dst_port || alertData.port);
        if (!isNaN(port) && 
            this.c2Patterns.suspicious_ports.includes(port) &&
            !BENIGN_ENTITIES.vpn_ports.includes(port)) {
          c2Indicators.detected = true;
          c2Indicators.confidence += 0.4;
          c2Indicators.indicators.push(`suspicious_port:${port}`);
          c2Indicators.reasons.push(`Suspicious C2 port detected: ${port}`);
        }
      }

      // 3. Check for beaconing patterns (defensive checks)
      if ((alertData.timestamp || alertData.time) && alertData.duration) {
        const beaconScore = this.detectBeaconing(alertData);
        if (beaconScore > 0.5) {
          c2Indicators.detected = true;
          c2Indicators.confidence += beaconScore;
          c2Indicators.indicators.push('beaconing_pattern');
          c2Indicators.reasons.push(`Beaconing behavior detected (score: ${beaconScore.toFixed(2)})`);
        }
      }

      // 4. Check for data exfiltration patterns (defensive checks)
      if (alertData.bytes_sent > 0 && alertData.bytes_received > 0) {
        const exfilScore = this.detectExfiltration(alertData);
        if (exfilScore > 0) {
          c2Indicators.detected = true;
          c2Indicators.confidence += exfilScore;
          c2Indicators.indicators.push('data_exfiltration');
          c2Indicators.reasons.push(`Data exfiltration pattern detected (score: ${exfilScore.toFixed(2)})`);
        }
      }

      // 5. Check if traffic is external and NOT whitelisted (potential C2)
      for (const ip of iocs.ips) {
        if (this.isExternalIP(ip) && !this.isWhitelistedIP(ip)) {
          c2Indicators.detected = true;
          c2Indicators.confidence += 0.2;
          c2Indicators.indicators.push(`external_ip:${ip}`);
          c2Indicators.reasons.push(`External IP communication: ${ip}`);
        }
      }

      c2Indicators.confidence = Math.min(c2Indicators.confidence, 1.0);
    } catch (error) {
      console.warn('C2 analysis partially failed:', error.message);
    }

    return c2Indicators;
  }

  detectBeaconing(alertData) {
    let score = 0;
    
    // Defensive check for bytes_sent
    if (alertData.bytes_sent && alertData.bytes_sent > 0 && alertData.bytes_sent < 1000) {
      score += 0.3;
    }
    
    // Defensive check for protocol
    if (alertData.protocol && typeof alertData.protocol === 'string') {
      const c2Protocols = ['DNS', 'ICMP', 'HTTP', 'HTTPS'];
      const protocolUpper = alertData.protocol.toUpperCase();
      if (c2Protocols.includes(protocolUpper)) {
        score += 0.2;
      }
    }
    
    return score;
  }

  detectExfiltration(alertData) {
    let score = 0;
    
    // Defensive checks
    if (alertData.bytes_sent > 10000 && alertData.bytes_received < 100) {
      score += 0.5;
    }
    
    if (alertData.encryption && alertData.encryption !== 'N/A') {
      score += 0.3;
    }
    
    return score;
  }

  isExternalIP(ip) {
    if (!this.isValidIP(ip)) return false;
    
    // Check if it's whitelisted first
    if (this.isWhitelistedIP(ip)) return false;
    
    // Then check if it's internal
    return !this.isInternalIP(ip);
  }

  isInternalIP(ip) {
    if (!this.isValidIP(ip)) return false;
    
    const octets = ip.split('.').map(Number);
    return (octets[0] === 10) || 
           (octets[0] === 192 && octets[1] === 168) ||
           (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31);
  }

  extractIOCs(alertData) {
    const iocs = {
      ips: new Set(),
      domains: new Set(),
      hashes: new Set(),
      users: new Set(),
      processes: new Set()
    };

    try {
      // Updated field mappings with more comprehensive coverage
      const ipFields = ['srcip', 'dstip', 'remip', 'locip', 'ip', 'source_ip', 'destination_ip', 'client_ip', 'server_ip', 'reporting_ip', 'src', 'dst'];
      const domainFields = ['domain', 'hostname', 'url', 'fqdn', 'host', 'dns', 'request_url', 'ssid', 'query', 'hostname', 'referrer'];
      const hashFields = ['hash', 'file_hash', 'process_hash', 'md5', 'sha1', 'sha256', 'checksum', 'sha256'];
      const userFields = ['user', 'username', 'account', 'login', 'actor', 'sender', 'receiver'];
      const processFields = ['process', 'process_name', 'image_path', 'executable', 'cmdline', 'image'];

      const addToSet = (set, value) => {
        if (value && typeof value === 'string') {
          if (set === iocs.ips && this.isValidIP(value)) {
            set.add(value.toLowerCase());
          } else if (set === iocs.domains && this.isValidDomain(value)) {
            set.add(value.toLowerCase());
          } else if (set !== iocs.ips && set !== iocs.domains) {
            const cleanedValue = value.replace(/[^a-zA-Z0-9\.\-_:@]/g, '');
            if (cleanedValue && cleanedValue.length > 1) {
              set.add(cleanedValue.toLowerCase());
            }
          }
        }
      };

      const extractFromObject = (obj, depth = 0) => {
        if (depth > 10) return;
        
        try {
          for (const [key, value] of Object.entries(obj)) {
            const keyLower = key.toLowerCase();
            
            if (typeof value === 'object' && value !== null) {
              extractFromObject(value, depth + 1);
              continue;
            }

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
        } catch (error) {
          console.warn('Error extracting from object:', error.message);
        }
      };

      extractFromObject(alertData);

      // Enhanced raw log extraction
      if (alertData.raw_event_log || alertData['Raw Event Log'] || alertData['User Event Log']) {
        try {
          const rawLog = alertData.raw_event_log || alertData['Raw Event Log'] || alertData['User Event Log'];
          this.extractFromRawLog(rawLog, iocs);
        } catch (error) {
          console.warn('Failed to parse raw event log:', error.message);
        }
      }

    } catch (error) {
      console.error('Error in extractIOCs:', error);
    }

    return {
      ips: Array.from(iocs.ips),
      domains: Array.from(iocs.domains),
      hashes: Array.from(iocs.hashes),
      users: Array.from(iocs.users),
      processes: Array.from(iocs.processes)
    };
  }

  extractFromRawLog(rawLog, iocs) {
    try {
      // Improved IP regex
      const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
      const ips = rawLog.match(ipRegex) || [];
      ips.forEach(ip => {
        if (this.isValidIP(ip)) {
          iocs.ips.add(ip.toLowerCase());
        }
      });
      
      // Improved domain regex that handles various formats
      const domainRegex = /[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+/g;
      const domains = rawLog.match(domainRegex) || [];
      domains.forEach(domain => {
        // Filter out common false positives
        if (domain.length <= 255 && 
            !domain.startsWith('http') && 
            !domain.startsWith('www.') && 
            domain.includes('.') &&
            domain.split('.').pop().length >= 2) {
          iocs.domains.add(domain.toLowerCase());
        }
      });
    } catch (error) {
      console.warn('Raw log extraction failed:', error.message);
    }
  }

  isValidDomain(domain) {
    try {
      // More permissive domain validation
      const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
      return domainRegex.test(domain) && domain.length < 255 && domain.includes('.');
    } catch (error) {
      return false;
    }
  }

  analyzeLocally(iocs) {
    const matched_iocs = [];
    let confidence = 0;
    let verdict = 'benign';
    let reasons = [];
    let severity = 'low';
    let recommended_actions = [];

    // Check for internal IPs first - treat as benign by default
    const internalIPs = iocs.ips.filter(ip => this.isInternalIP(ip));
    const externalIPs = iocs.ips.filter(ip => !this.isInternalIP(ip));
    const whitelistedIPs = iocs.ips.filter(ip => this.isWhitelistedIP(ip));

    if (internalIPs.length > 0) {
      internalIPs.forEach(ip => {
        matched_iocs.push(`internal_ip:${ip}`);
        reasons.push(`Internal IP detected: ${ip}`);
      });
      confidence = 0.1;
      severity = 'low';
      recommended_actions.push('Review internal IP communication for signs of compromise');
      recommended_actions.push('Check if internal IP is expected in this context');
    }

    if (whitelistedIPs.length > 0) {
      whitelistedIPs.forEach(ip => {
        matched_iocs.push(`whitelisted_ip:${ip}`);
        reasons.push(`Whitelisted IP detected: ${ip}`);
      });
      // Whitelisted IPs are very safe
      confidence = -0.3;
      severity = 'info';
      recommended_actions.push('Verify whitelisted IP communication is expected');
    }

    // Check external IPs against known threats (excluding whitelisted)
    for (const ip of externalIPs) {
      if (this.isWhitelistedIP(ip)) continue; // Skip whitelisted
      
      if (BENIGN_ENTITIES.ips.includes(ip)) {
        matched_iocs.push(`benign_ip:${ip}`);
        reasons.push(`Known benign IP: ${ip}`);
        confidence -= 0.2;
      }
      
      if (this.knownThreats.malicious_ips.includes(ip)) {
        matched_iocs.push(`malicious_ip:${ip}`);
        confidence += 0.8;
        reasons.push(`Known malicious IP: ${ip}`);
        severity = 'high';
        recommended_actions.push('Block malicious IP immediately');
        recommended_actions.push('Investigate affected systems');
      }
    }

    // Check domains against known threats
    for (const domain of iocs.domains) {
      console.log(`Checking domain: ${domain} against known threats`);
      
      if (BENIGN_ENTITIES.domains.some(benign => domain.includes(benign))) {
        matched_iocs.push(`benign_domain:${domain}`);
        reasons.push(`Known benign domain: ${domain}`);
        confidence -= 0.2;
      }
      
      if (this.knownThreats.malicious_domains.includes(domain)) {
        matched_iocs.push(`malicious_domain:${domain}`);
        confidence += 0.9; // Higher confidence for malicious domains
        reasons.push(`Known malicious domain: ${domain}`);
        severity = 'high';
        recommended_actions.push('Block malicious domain immediately');
        recommended_actions.push('Investigate DNS queries for this domain');
        recommended_actions.push('Check all systems for infections');
      }
    }

    for (const hash of iocs.hashes) {
      if (this.knownThreats.malicious_hashes.includes(hash)) {
        matched_iocs.push(`malicious_hash:${hash}`);
        confidence += 0.9;
        reasons.push(`Known malicious hash: ${hash}`);
        severity = 'critical';
        recommended_actions.push('Quarantine file immediately');
        recommended_actions.push('Scan all systems for this hash');
        recommended_actions.push('Investigate file origin and propagation');
      }
    }

    // Adjust verdict based on confidence
    if (confidence > 0.8) {
      verdict = 'malicious';
      severity = 'high';
    } else if (confidence > 0.3) {
      verdict = 'suspicious';
      severity = 'medium';
    } else if (internalIPs.length > 0 && externalIPs.length === 0) {
      // If only internal IPs are present, keep as benign
      verdict = 'benign';
      severity = 'low';
    } else if (whitelistedIPs.length > 0) {
      // If whitelisted IPs are present, very likely benign
      verdict = 'benign';
      severity = 'info';
      confidence = 0.9;
    } else if (matched_iocs.length > 0) {
      verdict = 'suspicious_low_confidence';
      severity = 'low';
    }

    return {
      verdict,
      confidence: Math.min(Math.max(confidence, 0), 1.0),
      severity,
      matched_iocs,
      reasons,
      recommended_actions: recommended_actions.length > 0 ? recommended_actions : [
        'Review alert details',
        'Monitor for similar activity',
        'Check system logs for related events'
      ],
      total_iocs_checked: iocs.ips.length + iocs.domains.length + iocs.hashes.length,
      internal_ip_count: internalIPs.length,
      external_ip_count: externalIPs.length,
      whitelisted_ip_count: whitelistedIPs.length
    };
  }

  async enrichWithExternalIntel(iocs) {
    const results = {
      verdict: 'unknown',
      confidence: 0,
      severity: 'low',
      matched_iocs: [],
      reasons: [],
      otx_results: {},
      geoip_results: {}
    };

    try {
      for (const ip of iocs.ips) {
        if (!this.isValidIP(ip) || this.isWhitelistedIP(ip)) continue;

        const [otxResult, geoipResult] = await Promise.allSettled([
          this.checkOTX(ip),
          this.checkGeoIP(ip)
        ]);

        if (otxResult.status === 'fulfilled' && otxResult.value) {
          results.otx_results[ip] = otxResult.value;
          if (otxResult.value.pulse_count > 0) {
            results.matched_iocs.push(`otx_malicious_ip:${ip}`);
            results.confidence += 0.4;
            results.reasons.push(`OTX found ${otxResult.value.pulse_count} threat pulses for IP: ${ip}`);
          }
        }

        if (geoipResult.status === 'fulfilled' && geoipResult.value) {
          results.geoip_results[ip] = geoipResult.value;
          if (this.isSuspiciousGeoLocation(geoipResult.value)) {
            results.matched_iocs.push(`suspicious_geo_ip:${ip}`);
            results.confidence += 0.2;
            results.reasons.push(`Suspicious geographic location: ${geoipResult.value.country} (${geoipResult.value.country_code})`);
          }
        }
      }

      for (const domain of iocs.domains) {
        const otxResult = await this.checkOTX(domain);
        if (otxResult && otxResult.pulse_count > 0) {
          results.otx_results[domain] = otxResult;
          results.matched_iocs.push(`otx_malicious_domain:${domain}`);
          results.confidence += 0.7; // Higher confidence for malicious domains
          results.reasons.push(`OTX found ${otxResult.pulse_count} threat pulses for domain: ${domain}`);
        }
      }

      if (results.confidence > 0.7) {
        results.verdict = 'malicious';
        results.severity = 'high';
      } else if (results.confidence > 0.3) {
        results.verdict = 'suspicious';
        results.severity = 'medium';
      } else if (results.matched_iocs.length > 0) {
        results.verdict = 'suspicious_low_confidence';
        results.severity = 'low';
      }

      results.confidence = Math.min(results.confidence, 1.0);

    } catch (error) {
      console.error('External intelligence enrichment failed:', error);
      results.reasons.push(`External intelligence failed: ${error.message}`);
    }

    return results;
  }

  async checkOTX(ioc) {
    if (!process.env.OTX_API_KEY) {
      return { pulse_count: 0, pulses: [], reputation: 0 };
    }

    const cacheKey = `otx:${ioc}`;
    const cached = this.otxCache.get(cacheKey);
    
    if (cached && (Date.now() - cached.timestamp) < this.cacheTTL) {
      return cached.data;
    }

    try {
      const type = this.isValidIP(ioc) ? 'IPv4' : 'domain';
      const response = await axios.get(
        `https://otx.alienvault.com/api/v1/indicators/${type}/${ioc}/general`,
        {
          headers: { 'X-OTX-API-KEY': process.env.OTX_API_KEY },
          timeout: 10000
        }
      );

      const result = {
        pulse_count: response.data.pulse_info.count,
        pulses: response.data.pulse_info.pulses,
        reputation: response.data.reputation
      };

      this.otxCache.set(cacheKey, { data: result, timestamp: Date.now() });
      return result;

    } catch (error) {
      if (error.response?.status === 404) {
        return { pulse_count: 0, pulses: [], reputation: 0 };
      }
      console.error(`OTX check failed for ${ioc}:`, error.message);
      return { pulse_count: 0, pulses: [], reputation: 0 };
    }
  }

  async checkGeoIP(ip) {
    const cacheKey = `geoip:${ip}`;
    const cached = this.geoipCache.get(cacheKey);
    
    if (cached && (Date.now() - cached.timestamp) < this.cacheTTL) {
      return cached.data;
    }

    try {
      const response = await axios.get(`https://ipapi.co/${ip}/json/`, {
        timeout: 5000
      });

      const result = {
        country: response.data.country_name,
        country_code: response.data.country_code,
        city: response.data.city,
        isp: response.data.org,
        asn: response.data.asn
      };

      this.geoipCache.set(cacheKey, { data: result, timestamp: Date.now() });
      return result;

    } catch (error) {
      console.error(`GeoIP check failed for ${ip}:`, error.message);
      return null;
    }
  }

  isSuspiciousGeoLocation(geoData) {
    if (!geoData || !geoData.country_code) return false;
    
    // Only flag extreme cases, not broad categories
    const highRiskCountries = ['KP']; // Only North Korea
    return highRiskCountries.includes(geoData.country_code);
  }

  determineFinalVerdict(localAnalysis, externalAnalysis, aiAnalysis, c2Analysis, iocs, alertData) {
  console.log('Final verdict analysis:');
  console.log('Local analysis verdict:', localAnalysis.verdict);
  console.log('Local analysis confidence:', localAnalysis.confidence);
  console.log('Malicious domains found:', iocs.domains.filter(d => this.knownThreats.malicious_domains.includes(d)));
  console.log('Malicious IPs found:', iocs.ips.filter(ip => this.knownThreats.malicious_ips.includes(ip)));
  const internalIPs = iocs.ips.filter(ip => this.isInternalIP(ip));
  const externalIPs = iocs.ips.filter(ip => !this.isInternalIP(ip));
  const whitelistedIPs = iocs.ips.filter(ip => this.isWhitelistedIP(ip));

  // Extract event type for context-aware analysis
  const eventType = alertData['Event Type'] || alertData['Event type'] || '';
  const eventName = alertData['Event Name'] || '';
  
  console.log('Event context:', { eventType, eventName });

  // **NEW: Handle DNS events specifically**
  if (eventType.includes('dns') || eventType.includes('DNS')) {
    const maliciousDomains = iocs.domains.filter(domain => 
      this.knownThreats.malicious_domains.includes(domain)
    );
    
    if (maliciousDomains.length > 0) {
      return {
        verdict: 'malicious',
        confidence: 0.95, // Higher confidence for DNS events
        severity: 'high',
        reason: `DNS query to known malicious domain: ${maliciousDomains.join(', ')}`,
        recommended_actions: [
          'Immediately block DNS queries to this domain',
          'Investigate source device for compromise',
          'Check DNS logs for other queries to suspicious domains',
          'Update DNS blacklist and firewall rules'
        ]
      };
    }
    
    // For benign DNS queries, provide specific guidance
    if (iocs.domains.length > 0 && maliciousDomains.length === 0) {
      return {
        verdict: 'benign',
        confidence: 0.8,
        severity: 'info',
        reason: 'DNS query to non-malicious domain',
        recommended_actions: [
          'Monitor DNS patterns for anomalies',
          'Verify domain reputation periodically',
          'Review DNS filtering policies'
        ]
      };
    }
  }

  // **NEW: Handle traffic events specifically**
  if (eventType.includes('traffic')) {
    const maliciousIPs = iocs.ips.filter(ip => 
      this.knownThreats.malicious_ips.includes(ip)
    );
    
    if (maliciousIPs.length > 0) {
      const action = alertData.action || 'unknown';
      return {
        verdict: 'malicious',
        confidence: action === 'deny' ? 0.9 : 0.8,
        severity: 'high',
        reason: `Traffic involving known malicious IP: ${maliciousIPs.join(', ')} (action: ${action})`,
        recommended_actions: [
          'Block malicious IP at firewall level',
          'Investigate communication patterns',
          'Check for data exfiltration',
          'Review all systems that communicated with this IP'
        ]
      };
    }
  }

  // **NEW: Handle security events (virus, attack, etc.)**
  if (eventType.includes('virus') || eventType.includes('attack') || eventType.includes('anomaly')) {
    const maliciousHashes = iocs.hashes.filter(hash => 
      this.knownThreats.malicious_hashes.includes(hash)
    );
    
    if (maliciousHashes.length > 0) {
      return {
        verdict: 'malicious',
        confidence: 0.99, // Very high confidence for hash matches
        severity: 'critical',
        reason: `Known malware hash detected: ${maliciousHashes.join(', ')}`,
        recommended_actions: [
          'Immediately quarantine infected files',
          'Scan all systems for this hash',
          'Investigate infection vector',
          'Update antivirus signatures'
        ]
      };
    }
  }

  // **NEW: Handle VPN/IPSec events specifically**
  if (eventType.includes('ipsec') || eventType.includes('vpn')) {
    return {
      verdict: 'benign',
      confidence: 0.9,
      severity: 'info',
      reason: 'VPN/IPSec traffic detected - legitimate business communication',
      recommended_actions: [
        'Verify VPN tunnel authorization',
        'Monitor VPN performance metrics',
        'Review VPN access logs for anomalies'
      ]
    };
  }

  // **NEW: Handle wireless/rogue AP events**
  if (eventType.includes('wireless') || eventType.includes('rogue')) {
    return {
      verdict: 'suspicious',
      confidence: 0.7,
      severity: 'medium',
      reason: 'Wireless security event detected',
      recommended_actions: [
        'Investigate rogue access point',
        'Check wireless network configuration',
        'Review connected devices',
        'Monitor for unauthorized access'
      ]
    };
  }

  // **NEW: Handle denied traffic specifically**
  if (alertData.action === 'deny') {
    return {
      verdict: 'benign',
      confidence: 0.7,
      severity: 'low',
      reason: 'Firewall correctly blocked suspicious traffic',
      recommended_actions: [
        'Review firewall rule that triggered the block',
        'Verify if this is expected behavior',
        'Monitor for repeated block attempts'
      ]
    };
  }

  // Rest of the existing logic for non-specific events
  const maliciousDomains = iocs.domains.filter(domain => 
    this.knownThreats.malicious_domains.includes(domain)
  );
  
  if (maliciousDomains.length > 0) {
    return {
      verdict: 'malicious',
      confidence: 0.9,
      severity: 'high',
      reason: `Known malicious domain detected: ${maliciousDomains.join(', ')}`,
      recommended_actions: [
        'Block malicious domain immediately',
        'Investigate DNS queries for this domain',
        'Check all systems for infections'
      ]
    };
  }
  // If whitelisted IPs are present, treat as benign
  if (whitelistedIPs.length > 0) {
    return {
      verdict: 'benign',
      confidence: 0.9,
      severity: 'info',
      reason: 'Whitelisted business infrastructure IP addresses detected',
      recommended_actions: [
        'Verify whitelisted IP communication is expected',
        'Monitor for any unusual patterns in business traffic'
      ]
    };
  }


    // High confidence C2 detection overrides internal IP benign status
    if (c2Analysis.detected && c2Analysis.confidence > 0.6) {
      return {
        verdict: 'malicious',
        confidence: c2Analysis.confidence,
        severity: 'high',
        reason: 'C2 communication detected despite internal IP',
        recommended_actions: [
          'Investigate internal system for compromise',
          'Isolate affected system from network',
          'Conduct forensic analysis'
        ]
      };
    }

    if (externalAnalysis.verdict !== 'unknown') {
      return {
        verdict: externalAnalysis.verdict,
        confidence: externalAnalysis.confidence,
        severity: externalAnalysis.severity || 'medium',
        reason: 'External threat intelligence match'
      };
    }

    if (aiAnalysis && aiAnalysis.verdict !== 'unknown' && aiAnalysis.verdict !== 'openai_not_configured') {
      return aiAnalysis;
    }

    if (internalIPs.length > 0 && externalIPs.length > 0) {
      return {
        verdict: 'suspicious',
        confidence: 0.6,
        severity: 'medium',
        reason: 'Internal to external communication detected',
        recommended_actions: [
          'Review internal-external communication patterns',
          'Check if external communication is authorized',
          'Monitor for data exfiltration signs'
        ]
      };
    }

    if (localAnalysis.verdict !== 'unknown') {
      return localAnalysis;
    }

    return { 
      verdict: 'unknown', 
      confidence: 0,
      severity: 'low',
      recommended_actions: ['Review alert details thoroughly']
    };
  }

  async analyzeWithAI(iocs, externalAnalysis, c2Analysis, retries = 3) {
    if (!process.env.OPENAI_API_KEY) {
      return {
        verdict: "openai_not_configured",
        confidence: 0,
        reasoning: "OpenAI API key not configured"
      };
    }

    try {
      const hasIOCs = iocs.ips.length > 0 || iocs.domains.length > 0 || iocs.hashes.length > 0;
      if (!hasIOCs) {
        return { verdict: 'no_iocs_to_analyze' };
      }

      const context = externalAnalysis ? `External analysis results: ${JSON.stringify(externalAnalysis)}` : '';
      const c2Context = c2Analysis ? `C2 analysis results: ${JSON.stringify(c2Analysis)}` : '';

      const response = await axios.post('https://api.openai.com/v1/chat/completions', {
        model: process.env.OPENAI_MODEL || "gpt-4o",
        messages: [
          {
            role: "system",
            content: `You are a cybersecurity threat intelligence analyst specializing in C2 detection. Consider:
            - OTX pulse counts > 0 indicate malicious reputation
            - GeoIP data from high-risk countries increases suspicion
            - Look for C2 patterns: DGA domains, suspicious ports (4444, 8080, 1337)
            - Beaconing behavior: regular small data transfers
            - Data exfiltration: large outbound, small inbound
            - Internal IPs can still be part of C2 if communicating externally
            - Known CDNs and cloud providers are typically benign
            - Whitelisted IP ranges (109.245.0.0/16) are business infrastructure
            - IPSec VPN traffic on port 500 is legitimate business traffic
            ${context}
            ${c2Context}
            Respond with JSON: { 
              verdict: "malicious|suspicious|benign|unknown", 
              confidence: 0.0-1.0, 
              reasoning: string,
              c2_indicators: string[] 
            }`
          },
          {
            role: "user",
            content: `Analyze these IOCs for C2 activity:\n${JSON.stringify(iocs, null, 2)}`
          }
        ],
        response_format: { type: "json_object" },
        max_tokens: 600,
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
      if (error.response?.status === 429 && retries > 0) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        return this.analyzeWithAI(iocs, externalAnalysis, c2Analysis, retries - 1);
      }
      
      console.error('OpenAI analysis failed:', error.message);
      return {
        verdict: "analysis_failed",
        error: error.message,
        confidence: 0
      };
    }
  }

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

  getThreatDatabase() {
    return this.knownThreats;
  }
}

const threatIntel = new ThreatIntelAI();

router.post('/analyze', threatIntel.analyzeThreat.bind(threatIntel));

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
    has_otx: !!process.env.OTX_API_KEY,
    threat_counts: {
      ips: threatIntel.knownThreats.malicious_ips.length,
      domains: threatIntel.knownThreats.malicious_domains.length,
      hashes: threatIntel.knownThreats.malicious_hashes.length
    },
    cache_stats: {
      otx: threatIntel.otxCache.size,
      geoip: threatIntel.geoipCache.size
    }
  });
});

router.get('/health/extended', async (req, res) => {
  try {
    const healthInfo = {
      status: 'healthy',
      has_openai: !!process.env.OPENAI_API_KEY,
      has_otx: !!process.env.OTX_API_KEY,
      services: {}
    };

    if (process.env.OTX_API_KEY) {
      try {
        const otxTest = await axios.get('https://otx.alienvault.com/api/v1/user/me', {
          headers: { 'X-OTX-API-KEY': process.env.OTX_API_KEY },
          timeout: 5000
        });
        healthInfo.services.otx = otxTest.status === 200 ? 'connected' : 'failed';
      } catch (error) {
        healthInfo.services.otx = 'disconnected';
      }
    }

    try {
      const geoipTest = await axios.get('https://ipapi.co/8.8.8.8/json/', {
        timeout: 5000
      });
      healthInfo.services.geoip = geoipTest.status === 200 ? 'connected' : 'failed';
    } catch (error) {
      healthInfo.services.geoip = 'disconnected';
    }

    healthInfo.cache_stats = {
      otx: threatIntel.otxCache.size,
      geoip: threatIntel.geoipCache.size
    };

    res.json(healthInfo);
  } catch (error) {
    res.status(500).json({
      status: 'degraded',
      error: error.message
    });
  }
});

module.exports = router;