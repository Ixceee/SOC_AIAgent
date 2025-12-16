const express = require('express');
const router = express.Router();
const axios = require('axios');

class EnhancedEndpointAI {
  constructor() {
    this.ollamaAvailable = true;
    this.model = 'llama3.1:8b';
    
    // Enhanced VPN threat intelligence with internal threat detection
    this.vpnThreats = {
      // High-risk countries (expanded list)
      suspicious_vpn_countries: [
        'RU', 'CN', 'IR', 'KP', 'SY', 'VE', 'NG', 'BR', 'IN',
        'VN', 'UA', 'TR', 'PK', 'BD', 'EG', 'TH', 'PH', 'MY'
      ],
      
      // Enhanced VPN failure codes with severity
      vpn_failure_codes: {
        'peer SA proposal not match local policy': 'critical',
        'authentication failed': 'critical',
        'handshake_failure': 'high',
        'certificate_unknown': 'high',
        'access_denied': 'medium',
        'decrypt_error': 'high',
        'timeout': 'medium',
        'connection reset': 'medium',
        'close notify': 'low',
        'no proposal chosen': 'critical'
      },
      
      // Suspicious SSL alerts
      suspicious_ssl_alerts: [
        'handshake_failure', 'certificate_unknown', 'access_denied',
        'decrypt_error', 'bad_certificate', 'unsupported_certificate',
        'certificate_revoked', 'certificate_expired', 'unknown_ca'
      ],
      
      // Internal threat indicators for VPN
      internal_threat_indicators: {
        // VPN connections from internal IPs (should be suspicious)
        vpn_from_internal_ip: 'high',
        
        // VPN to critical internal systems
        vpn_to_critical_systems: ['domaincontroller', 'fileserver', 'database', 'ad', 'dc'],
        
        // Unusual VPN connection times (outside business hours)
        unusual_hours: {
          business_hours: { start: 9, end: 17 },
          weekend: 'suspicious'
        },
        
        // VPN tunnel types with different risk levels
        tunnel_type_risk: {
          'ssl': 'medium',
          'ipsec': 'low',
          'gre': 'high',
          'l2tp': 'high',
          'pptp': 'critical'  // Very insecure
        }
      },
      
      // User account risk indicators
      suspicious_users: [
        'admin', 'root', 'administrator', 'test', 'guest', 'user',
        'svc_', 'service_', 'backup', 'monitor'
      ]
    };
  }

  // Enhanced address extraction with internal IP detection
  extractAddresses(log) {
    console.log('🔍 ENHANCED ENDPOINTAI - Extracting addresses with VPN context');
    
    let source_address = 'Unknown';
    let destination_address = 'Unknown';
    let source_is_mac = false;
    let destination_is_mac = false;
    let source_is_internal = false;
    let destination_is_internal = false;
    let source_is_critical = false;
    let destination_is_critical = false;
    
    // For VPN events, look for remote and local IPs
    if (log.remip && log.remip !== 'N/A' && log.remip !== 'Unknown') {
      source_address = log.remip;
      source_is_internal = this.isInternalIP(log.remip);
      console.log(`🔐 Found VPN remote IP: ${source_address} (Internal: ${source_is_internal})`);
    }
    
    if (log.locip && log.locip !== 'N/A' && log.locip !== 'Unknown') {
      destination_address = log.locip;
      destination_is_internal = this.isInternalIP(log.locip);
      destination_is_critical = this.isCriticalSystem(log.locip, log.dst_hostname || '');
      console.log(`🔐 Found VPN local IP: ${destination_address} (Internal: ${destination_is_internal}, Critical: ${destination_is_critical})`);
    }
    
    // Fallback to standard IP fields
    const ipFields = ['srcip', 'dstip', 'src', 'dst', 'ip', 'source_ip', 'dest_ip'];
    for (const field of ipFields) {
      if (log[field] && this.isValidIP(log[field])) {
        if (source_address === 'Unknown') {
          source_address = log[field];
          source_is_internal = this.isInternalIP(log[field]);
        } else if (destination_address === 'Unknown') {
          destination_address = log[field];
          destination_is_internal = this.isInternalIP(log[field]);
        }
      }
    }
    
    // Check if addresses are critical systems
    if (log.src_hostname && this.isCriticalSystem('', log.src_hostname)) {
      source_is_critical = true;
    }
    if (log.dst_hostname && this.isCriticalSystem('', log.dst_hostname)) {
      destination_is_critical = true;
    }
    
    // Extract from raw log if needed
    if ((source_address === 'Unknown' || destination_address === 'Unknown') && log['Raw Event Log']) {
      const rawLog = log['Raw Event Log'];
      const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
      const ips = rawLog.match(ipRegex) || [];
      
      if (ips.length >= 2) {
        if (source_address === 'Unknown') {
          source_address = ips[0];
          source_is_internal = this.isInternalIP(ips[0]);
        }
        if (destination_address === 'Unknown') {
          destination_address = ips[1];
          destination_is_internal = this.isInternalIP(ips[1]);
        }
      } else if (ips.length === 1 && source_address === 'Unknown') {
        source_address = ips[0];
        source_is_internal = this.isInternalIP(ips[0]);
      }
    }
    
    return {
      source_address,
      destination_address,
      source_is_mac,
      destination_is_mac,
      source_is_internal,
      destination_is_internal,
      source_is_critical,
      destination_is_critical,
      is_vpn_connection: !!(log.remip || log.locip || log.tunneltype),
      tunnel_type: log.tunneltype || 'Unknown',
      user: log.user || 'N/A'
    };
  }

  // Enhanced VPN risk assessment with internal threat detection
  assessVPNRisk(alert, addresses) {
    const action = alert.action || 'Unknown';
    const status = alert.status || 'Unknown';
    const reason = alert.reason || 'Not provided';
    const desc = alert.desc || 'Not provided';
    const user = alert.user || 'N/A';
    const group = alert.group || 'N/A';
    const remip = alert.remip || 'Unknown';
    const srccountry = alert.srccountry || 'Unknown';
    const tunneltype = alert.tunneltype || 'Unknown';
    const timestamp = alert.eventtime || alert.time || new Date().toISOString();
    
    let threat_level = 'low';
    let attack_type = 'vpn_event';
    let confidence = 0.5;
    let key_findings = [`VPN ${action} event`];
    let immediate_actions = ['Review VPN logs'];
    let investigation_steps = ['Check VPN configuration'];
    let business_impact = 'low';
    
    // CRITICAL: VPN authentication failures (potential brute force)
    if (status === 'failed' && reason?.toLowerCase().includes('authentication')) {
      threat_level = 'critical';
      attack_type = 'vpn_credential_attack';
      confidence = 0.9;
      business_impact = 'high';
      key_findings.push('🚨 VPN AUTHENTICATION FAILURE - Possible brute force attack');
      immediate_actions = [
        'IMMEDIATE: Lock VPN account',
        'Review authentication logs for patterns',
        'Check for credential stuffing'
      ];
      investigation_steps = [
        'Analyze failed login attempts',
        'Check if user credentials are compromised',
        'Review account lockout policies'
      ];
    }
    
    // CRITICAL: IPsec configuration mismatch (potential attack probing)
    if (reason?.includes('peer SA proposal not match') || 
        desc?.includes('no proposal chosen')) {
      threat_level = 'critical';
      attack_type = 'ipsec_configuration_attack';
      confidence = 0.8;
      key_findings.push('IPsec configuration mismatch - Possible attack probing');
      immediate_actions.push('Review IPsec policies and proposals');
      investigation_steps.push('Check for VPN gateway spoofing');
    }
    
    // HIGH: SSL VPN security alerts
    if (action === 'ssl-alert') {
      threat_level = 'high';
      attack_type = 'ssl_vpn_security_alert';
      confidence = 0.7;
      key_findings.push(`SSL VPN security alert: ${desc}`);
      
      // Check for specific high-risk SSL alerts
      if (this.vpnThreats.suspicious_ssl_alerts.some(alert => desc.toLowerCase().includes(alert))) {
        threat_level = 'critical';
        key_findings.push(`Critical SSL alert detected: ${desc}`);
        immediate_actions.push('Verify SSL certificates and trust chain');
        investigation_steps.push('Check for man-in-the-middle attacks');
      }
    }
    
    // HIGH: VPN connection from high-risk country
    if (this.vpnThreats.suspicious_vpn_countries.includes(srccountry)) {
      threat_level = Math.max(this.threatLevelToNumber(threat_level), this.threatLevelToNumber('high'));
      attack_type = 'vpn_from_high_risk_country';
      key_findings.push(`VPN connection from high-risk country: ${srccountry}`);
      immediate_actions.push('Review geo-blocking policies');
      investigation_steps.push('Check if this is expected business traffic');
    }
    
    // HIGH: VPN from internal IP (potential lateral movement)
    if (addresses.source_is_internal && addresses.is_vpn_connection) {
      threat_level = Math.max(this.threatLevelToNumber(threat_level), this.threatLevelToNumber('high'));
      attack_type = 'internal_vpn_connection';
      key_findings.push(`VPN connection FROM internal IP ${remip} - Possible lateral movement`);
      immediate_actions.push('Investigate internal host for compromise');
      investigation_steps.push('Check for pivoting from internal network');
    }
    
    // HIGH: VPN to critical internal system
    if (addresses.destination_is_critical && addresses.is_vpn_connection) {
      threat_level = Math.max(this.threatLevelToNumber(threat_level), this.threatLevelToNumber('high'));
      attack_type = 'vpn_to_critical_system';
      key_findings.push(`VPN connection TO critical system: ${addresses.destination_address}`);
      immediate_actions.push('Review access controls for critical systems');
      investigation_steps.push('Verify user authorization for system access');
    }
    
    // MEDIUM: Suspicious user account
    if (user !== 'N/A') {
      const isSuspiciousUser = this.vpnThreats.suspicious_users.some(su => 
        user.toLowerCase().includes(su.toLowerCase()));
      
      if (isSuspiciousUser) {
        threat_level = Math.max(this.threatLevelToNumber(threat_level), this.threatLevelToNumber('medium'));
        attack_type = 'suspicious_vpn_user';
        key_findings.push(`Suspicious user account used for VPN: ${user}`);
        investigation_steps.push('Review user account permissions and activity');
      }
    }
    
    // MEDIUM: Weak VPN tunnel type
    const tunnelRisk = this.vpnThreats.internal_threat_indicators.tunnel_type_risk[tunneltype.toLowerCase()];
    if (tunnelRisk === 'critical' || tunnelRisk === 'high') {
      threat_level = Math.max(this.threatLevelToNumber(threat_level), this.threatLevelToNumber('medium'));
      key_findings.push(`Weak VPN tunnel type: ${tunneltype} (${tunnelRisk} risk)`);
      immediate_actions.push('Consider upgrading to more secure VPN protocol');
    }
    
    // LOW: Normal VPN operations
    if (key_findings.length === 1 && status === 'success') {
      threat_level = 'low';
      attack_type = 'normal_vpn_operation';
      key_findings = ['Normal VPN connection established'];
      business_impact = 'low';
    }
    
    return {
      threat_level: this.numberToThreatLevel(this.threatLevelToNumber(threat_level)),
      attack_type,
      confidence,
      key_findings,
      immediate_actions,
      investigation_steps,
      business_impact,
      vpn_analysis: {
        remote_ip: remip,
        local_ip: alert.locip || 'Unknown',
        country: srccountry,
        user,
        group,
        tunnel_type: tunneltype,
        status,
        reason,
        description: desc,
        is_high_risk_country: this.vpnThreats.suspicious_vpn_countries.includes(srccountry),
        is_internal_source: addresses.source_is_internal,
        is_critical_destination: addresses.destination_is_critical,
        timestamp: this.parseTimestamp(timestamp)
      }
    };
  }

  // Parse timestamp to check for unusual hours
  parseTimestamp(timestamp) {
    try {
      // Handle various timestamp formats
      let date;
      if (typeof timestamp === 'string') {
        // Check if it's a Unix timestamp (in milliseconds or seconds)
        if (/^\d+$/.test(timestamp)) {
          const num = parseInt(timestamp);
          // If it's in seconds (common in logs), convert to milliseconds
          date = new Date(num > 1000000000000 ? num : num * 1000);
        } else {
          // Try to parse as ISO string or other date string
          date = new Date(timestamp);
        }
      } else if (typeof timestamp === 'number') {
        date = new Date(timestamp > 1000000000000 ? timestamp : timestamp * 1000);
      } else {
        date = new Date();
      }
      
      if (isNaN(date.getTime())) {
        return { raw: timestamp, hour: -1, is_weekend: false, is_unusual_hours: false };
      }
      
      const hour = date.getHours();
      const day = date.getDay(); // 0 = Sunday, 6 = Saturday
      const isWeekend = day === 0 || day === 6;
      const isBusinessHours = hour >= 9 && hour <= 17;
      
      return {
        raw: timestamp,
        parsed: date.toISOString(),
        hour,
        day,
        is_weekend: isWeekend,
        is_business_hours: isBusinessHours && !isWeekend,
        is_unusual_hours: !isBusinessHours || isWeekend
      };
    } catch (error) {
      return { raw: timestamp, hour: -1, is_weekend: false, is_unusual_hours: false };
    }
  }

  // Check if IP is internal
  isInternalIP(ip) {
    if (!ip || ip === 'Unknown') return false;
    
    // Private IP ranges
    const internalRanges = [
      '10.', '172.16.', '172.17.', '172.18.', '172.19.',
      '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
      '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
      '172.30.', '172.31.', '192.168.'
    ];
    
    return internalRanges.some(range => ip.startsWith(range));
  }

  // Check if system is critical
  isCriticalSystem(ip, hostname) {
    if (!hostname) hostname = '';
    
    // Check by hostname
    const lowerHostname = hostname.toLowerCase();
    const isCriticalByName = this.vpnThreats.internal_threat_indicators.vpn_to_critical_systems
      .some(system => lowerHostname.includes(system));
    
    // Critical internal IPs (network infrastructure)
    const criticalIPs = [
      '192.168.1.1', '192.168.1.254', '10.0.0.1', '10.0.0.254',
      '172.16.0.1', '172.16.0.254', '192.168.0.1', '192.168.0.254'
    ];
    
    const isCriticalByIP = criticalIPs.includes(ip);
    
    return isCriticalByName || isCriticalByIP;
  }

  // Convert threat level to number for comparison
  threatLevelToNumber(level) {
    const levels = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 };
    return levels[level] || 1;
  }

  // Convert number to threat level
  numberToThreatLevel(num) {
    const levels = { 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' };
    return levels[num] || 'low';
  }

  // Enhanced rule-based analysis
  getRuleBasedAnalysis(alert) {
    console.log('🔍 ENHANCED ENDPOINTAI - Rule-based analysis for:', alert['Event Type'] || 'Unknown');
    
    const addresses = this.extractAddresses(alert);
    const subtype = alert.subtype || '';
    const logdesc = alert.logdesc || '';
    
    // VPN events
    if (subtype === 'vpn' || logdesc.includes('VPN') || logdesc.includes('IPsec') || addresses.is_vpn_connection) {
      return {
        ...this.assessVPNRisk(alert, addresses),
        _analyzed_by: 'endpoint_vpn_engine',
        _analysis_method: 'rule_based'
      };
    }
    
    // Default analysis for other endpoint events
    return {
      threat_level: 'low',
      attack_type: 'endpoint_event',
      confidence: 0.5,
      key_findings: ['Endpoint security event detected'],
      immediate_actions: ['Review endpoint logs'],
      investigation_steps: ['Check system integrity'],
      business_impact: 'low',
      _analyzed_by: 'endpoint_generic_engine',
      _analysis_method: 'rule_based'
    };
  }

  // Enhanced AI analysis with better prompt engineering
  async getAIAnalysis(alert) {
    if (!this.ollamaAvailable) {
      console.log('🔍 ENHANCED ENDPOINTAI - Ollama not available, using rule-based');
      return this.getRuleBasedAnalysis(alert);
    }

    const addresses = this.extractAddresses(alert);
    
    const prompt = `
CRITICAL SECURITY ANALYSIS - VPN & ENDPOINT THREAT DETECTION v2.0

You are Llama 3.1, an advanced AI security analyst specializing in VPN security, endpoint protection, and remote access threats.

INCIDENT CONTEXT:
- Event Type: ${alert['Event Type'] || 'Unknown'}
- Event Subtype: ${alert.subtype || 'None'}
- Log Description: ${alert.logdesc || 'Not provided'}
- Action: ${alert.action || 'Not provided'}
- Status: ${alert.status || 'Not provided'}
- Reason: ${alert.reason || 'Not provided'}
- Description: ${alert.desc || 'Not provided'}
- Source IP: ${addresses.source_address} (VPN Remote: ${alert.remip || 'N/A'}, Internal: ${addresses.source_is_internal})
- Destination IP: ${addresses.destination_address} (VPN Local: ${alert.locip || 'N/A'}, Internal: ${addresses.destination_is_internal})
- Source Country: ${alert.srccountry || 'Unknown'}
- User: ${alert.user || 'N/A'}
- Group: ${alert.group || 'N/A'}
- Tunnel Type: ${alert.tunneltype || 'Unknown'}
- Tunnel ID: ${alert.tunnelid || 'N/A'}
- Policy ID: ${alert.policyid || 'N/A'}
- Outgoing Interface: ${alert.outintf || 'Not provided'}
- Remote Port: ${alert.remport || 'Not provided'}
- Local Port: ${alert.locport || 'Not provided'}
- Critical System: ${addresses.destination_is_critical ? 'YES' : 'NO'}
- Raw Event Context: ${alert['Raw Event Log'] ? alert['Raw Event Log'].substring(0, 400) + '...' : 'Not provided'}

ENHANCED ANALYSIS FRAMEWORK FOR VPN & ENDPOINT THREATS:

1. VPN SECURITY THREATS:
   - VPN Authentication Bypass Attempts
   - IPsec/IKE Protocol Vulnerabilities
   - SSL/TLS Man-in-the-Middle Attacks
   - VPN Tunnel Hijacking
   - Credential Stuffing Attacks
   - Session Hijacking & Replay Attacks

2. INTERNAL THREATS VIA VPN:
   - Lateral Movement Through VPN (internal to internal)
   - Data Exfiltration via Encrypted Tunnels
   - Malware Distribution via VPN
   - Command & Control Through VPN
   - Privilege Escalation via VPN Sessions
   - Internal Host Compromise Leading to VPN Abuse

3. GEOGRAPHICAL & SOURCE THREATS:
   - Connections from High-Risk Countries
   - VPN Connections FROM Internal IPs (Red Flag)
   - TOR/VPN Exit Node Detection
   - Geographic Anomalies (User in Country A, VPN from Country B)

4. CRITICAL SYSTEM ACCESS:
   - VPN Access to Domain Controllers
   - VPN Access to Database Servers
   - VPN Access to File Servers
   - VPN Access to Management Interfaces

CRITICAL RISK INDICATORS (PRIORITIZE THESE):
- VPN failures with "authentication failed" = CRITICAL RISK
- VPN connections FROM internal IP addresses = HIGH RISK (lateral movement)
- VPN connections TO critical internal systems = HIGH RISK
- Connections from sanctioned/high-risk countries = HIGH RISK
- SSL alerts with "handshake_failure" or "certificate_unknown" = HIGH RISK
- IPsec "peer SA proposal not match" = MEDIUM-HIGH RISK
- VPN connections at unusual hours = MEDIUM RISK
- Use of weak VPN protocols (PPTP, L2TP) = HIGH RISK

INTERNAL THREAT SCENARIOS TO CONSIDER:
1. Compromised internal host establishing VPN to external C2
2. Internal host pivoting through VPN to attack other internal systems
3. Unauthorized VPN access to critical infrastructure
4. Credential theft leading to VPN account compromise

MITRE ATT&CK MAPPING:
- T1078.003 - Valid Accounts: Cloud Accounts
- T1133 - External Remote Services
- T1550.002 - Use Alternate Authentication Material: Pass the Hash
- T1563.002 - Remote Service Session Hijacking
- T1573 - Encrypted Channel
- T1021 - Remote Services

REQUIRED OUTPUT FORMAT (STRICT VALID JSON):
{
  "threat_level": "low|medium|high|critical",
  "attack_type": "specific_vpn_threat_category",
  "confidence": 0.0-1.0,
  "key_findings": ["finding1", "finding2", "finding3"],
  "immediate_actions": ["action1", "action2", "action3"],
  "investigation_steps": ["step1", "step2", "step3"],
  "business_impact": "low|medium|high|critical",
  "mitre_techniques": ["T1078.003", "T1133"],
  "false_positive_likelihood": "low|medium|high",
  "internal_threat_indicators": {
    "has_internal_source": true/false,
    "has_critical_destination": true/false,
    "geographic_risk": "low|medium|high",
    "tunnel_security_risk": "low|medium|high"
  }
}

THREAT CATEGORY EXAMPLES:
- vpn_credential_attack: {"threat_level": "critical", "attack_type": "credential_stuffing", ...}
- internal_lateral_movement: {"threat_level": "high", "attack_type": "vpn_lateral_movement", ...}
- vpn_configuration_attack: {"threat_level": "high", "attack_type": "ipsec_misconfiguration", ...}
- vpn_geo_threat: {"threat_level": "high", "attack_type": "high_risk_country_connection", ...}
- normal_vpn_operation: {"threat_level": "low", "attack_type": "benign", ...}

THREAT LEVEL GUIDELINES:
- Critical: Active attack with immediate business impact (data breach, system compromise)
- High: Clear security violation requiring immediate investigation
- Medium: Suspicious activity requiring further analysis
- Low: Normal or minor anomaly

ANALYZE THIS VPN SECURITY EVENT AND PROVIDE YOUR ASSESSMENT:
`;

    try {
      console.log('🔍 ENHANCED ENDPOINTAI - Sending to Llama 3.1:8b for enhanced analysis...');
      
      const response = await axios.post('http://ollama:11434/api/generate', {
        model: this.model,
        prompt: prompt,
        stream: false,
        options: {
          temperature: 0.1,
          top_p: 0.9,
          num_predict: 500
        }
      }, {
        timeout: 30000
      });

      if (response.status !== 200) {
        throw new Error(`Ollama error: ${response.status}`);
      }

      const data = response.data;
      
      // JSON extraction with better error handling
      let jsonMatch = data.response.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        jsonMatch = data.response.match(/```json\n([\s\S]*?)\n```/);
        if (jsonMatch) jsonMatch = [jsonMatch[1]];
      }
      
      if (!jsonMatch) {
        jsonMatch = data.response.match(/```\n([\s\S]*?)\n```/);
        if (jsonMatch) jsonMatch = [jsonMatch[1]];
      }
      
      if (!jsonMatch) {
        throw new Error('No JSON found in AI response');
      }
      
      let result;
      try {
        result = JSON.parse(jsonMatch[0]);
      } catch (parseError) {
        // Try to fix common JSON issues
        const cleaned = jsonMatch[0]
          .replace(/'/g, '"')
          .replace(/,\s*}/g, '}')
          .replace(/,\s*]/g, ']')
          .replace(/(\w+):/g, '"$1":')
          .replace(/:\s*([^"\[\]\{\},\s]+)(?=\s*[,}\]])/g, ': "$1"');
        
        try {
          result = JSON.parse(cleaned);
        } catch (e) {
          console.error('JSON parse error after cleaning:', e.message);
          throw new Error(`Failed to parse AI response: ${e.message}`);
        }
      }
      
      // Ensure required fields exist
      result.threat_level = result.threat_level || 'low';
      result.attack_type = result.attack_type || 'unknown_vpn_event';
      result.confidence = result.confidence || 0.5;
      result.key_findings = result.key_findings || ['Analysis completed'];
      result.immediate_actions = result.immediate_actions || ['Review logs'];
      result.investigation_steps = result.investigation_steps || ['Investigate further'];
      
      // Add metadata
      result._analyzed_by = 'llama3.1_8b';
      result._model = this.model;
      result._prompt_engineered = true;
      result._analysis_method = 'ai_enhanced';
      result._timestamp = new Date().toISOString();
      
      console.log('🔍 ENHANCED ENDPOINTAI - AI Analysis result:', {
        threat_level: result.threat_level,
        attack_type: result.attack_type,
        confidence: result.confidence,
        internal_threats: result.internal_threat_indicators || 'none'
      });
      
      return result;

    } catch (error) {
      console.error('❌ ENHANCED ENDPOINTAI - AI analysis failed:', error.message);
      return this.getRuleBasedAnalysis(alert);
    }
  }

  // Validate IP address
  isValidIP(ip) {
    if (!ip || typeof ip !== 'string') return false;
    const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) return false;
    const octets = ip.split('.');
    return octets.every(octet => {
      const num = parseInt(octet, 10);
      return num >= 0 && num <= 255;
    });
  }

  // Main analysis method
  async analyze(alert) {
    console.log('🔍 ENHANCED ENDPOINTAI - Starting analysis for:', alert['Event Type'] || 'Unknown');
    
    try {
      if (this.ollamaAvailable) {
        const aiResult = await this.getAIAnalysis(alert);
        return aiResult;
      } else {
        return this.getRuleBasedAnalysis(alert);
      }
    } catch (error) {
      console.error('❌ ENHANCED ENDPOINTAI - Analysis failed:', error.message);
      return this.getRuleBasedAnalysis(alert);
    }
  }
}

// Create instance
const enhancedEndpointAI = new EnhancedEndpointAI();

// Express Routes
router.post('/analyze', async (req, res) => {
  const requestId = Math.random().toString(36).substring(2, 10);
  console.log(`[${requestId}] 📡 ENHANCED ENDPOINTAI - Processing VPN/Endpoint alert`);
  
  try {
    const alert = req.body;
    const addresses = enhancedEndpointAI.extractAddresses(alert);
    const analysisResult = await enhancedEndpointAI.analyze(alert);
    
    const response = {
      status: 'success',
      analysis: analysisResult,
      addresses: {
        source: addresses.source_address,
        source_type: addresses.source_is_internal ? 'internal_ip' : 'external_ip',
        destination: addresses.destination_address,
        destination_type: addresses.destination_is_internal ? 'internal_ip' : 'external_ip',
        is_vpn_connection: addresses.is_vpn_connection,
        tunnel_type: addresses.tunnel_type,
        user: addresses.user
      },
      internal_threat_analysis: {
        has_internal_source: addresses.source_is_internal,
        has_critical_destination: addresses.destination_is_critical,
        risk_factors: []
      },
      metadata: {
        analyzedAt: new Date().toISOString(),
        model: analysisResult._analyzed_by || 'rule_engine',
        analysis_method: analysisResult._analysis_method || 'rule_based',
        processingTime: '0.2s',
        request_id: requestId,
        agent: 'EnhancedEndpointAI',
        ollama_model: analysisResult._model || 'none',
        prompt_engineered: analysisResult._prompt_engineered || false,
        alert_type: alert['Event Type'] || 'Unknown',
        subtype: alert.subtype || 'None'
      }
    };
    
    // Add risk factors to internal threat analysis
    if (addresses.source_is_internal) {
      response.internal_threat_analysis.risk_factors.push('VPN connection FROM internal IP');
    }
    if (addresses.destination_is_critical) {
      response.internal_threat_analysis.risk_factors.push('VPN connection TO critical system');
    }
    
    console.log(`[${requestId}] ✅ ENHANCED ENDPOINTAI - Analysis complete:`, {
      threat_level: analysisResult.threat_level,
      attack_type: analysisResult.attack_type,
      internal_threat: addresses.source_is_internal || addresses.destination_is_critical
    });
    
    res.json(response);
    
  } catch (error) {
    console.error(`[${requestId}] ❌ ENHANCED ENDPOINTAI - Error:`, error.message);
    res.status(500).json({
      status: 'error',
      error: error.message,
      request_id: requestId,
      agent: 'EnhancedEndpointAI',
      timestamp: new Date().toISOString()
    });
  }
});

router.get('/health', async (req, res) => {
  try {
    const ollamaResponse = await axios.get('http://ollama:11434/api/tags', { timeout: 5000 });
    const models = ollamaResponse.data.models || [];
    const llamaAvailable = models.some(m => m.name.includes('llama3.1'));
    
    res.json({
      status: 'healthy',
      agent: 'EnhancedEndpointAI',
      model: 'llama3.1:8b',
      ollama_available: true,
      llama3_available: llamaAvailable,
      analysis_capabilities: [
        'vpn_security_analysis',
        'ipsec_threat_detection',
        'ssl_vpn_analysis',
        'authentication_anomalies',
        'geographic_threat_assessment',
        'internal_threat_detection',
        'critical_system_access_monitoring',
        'tunnel_security_assessment'
      ],
      threat_intelligence: {
        suspicious_countries: enhancedEndpointAI.vpnThreats.suspicious_vpn_countries.length,
        vpn_failure_codes: Object.keys(enhancedEndpointAI.vpnThreats.vpn_failure_codes).length,
        suspicious_users: enhancedEndpointAI.vpnThreats.suspicious_users.length,
        internal_threat_detection: 'ENABLED'
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.json({
      status: 'degraded',
      agent: 'EnhancedEndpointAI',
      model: 'llama3.1:8b',
      ollama_available: false,
      error: error.message,
      timestamp: new Date().toISOString(),
      capabilities: [
        'rule_based_vpn_analysis',
        'internal_threat_detection',
        'critical_system_monitoring'
      ]
    });
  }
});

router.get('/vpn-threats', (req, res) => {
  res.json({
    agent: 'EnhancedEndpointAI',
    vpn_threat_intelligence: {
      suspicious_countries: enhancedEndpointAI.vpnThreats.suspicious_vpn_countries,
      high_risk_failure_codes: Object.entries(enhancedEndpointAI.vpnThreats.vpn_failure_codes)
        .filter(([_, severity]) => severity === 'critical' || severity === 'high')
        .map(([code, _]) => code),
      internal_threat_indicators: enhancedEndpointAI.vpnThreats.internal_threat_indicators,
      suspicious_users: enhancedEndpointAI.vpnThreats.suspicious_users
    },
    analysis_methods: ['AI_Enhanced', 'Rule_Based'],
    supported_vpn_types: ['IPsec', 'SSL_VPN', 'IKEv1', 'IKEv2', 'PPTP', 'L2TP', 'GRE'],
    threat_levels: ['low', 'medium', 'high', 'critical'],
    internal_threat_detection: 'ACTIVE'
  });
});

router.post('/test-internal-vpn', (req, res) => {
  // Test endpoint for internal VPN threat detection
  const testAlert = {
    'Event Type': 'FortiGate-event-vpn-internal-test',
    'subtype': 'vpn',
    'remip': '192.168.1.100', // Internal IP
    'locip': '10.0.0.1', // Internal critical system
    'action': 'connect',
    'status': 'success',
    'user': 'admin',
    'srccountry': 'US',
    'tunneltype': 'ssl'
  };
  
  const addresses = enhancedEndpointAI.extractAddresses(testAlert);
  const analysis = enhancedEndpointAI.assessVPNRisk(testAlert, addresses);
  
  res.json({
    test: 'Internal VPN Threat Detection Test',
    alert: testAlert,
    addresses,
    analysis,
    verdict: analysis.threat_level === 'high' || analysis.threat_level === 'critical' ? 
             'INTERNAL THREAT DETECTED' : 'No internal threat detected'
  });
});

module.exports = router;
module.exports.EnhancedEndpointAI = EnhancedEndpointAI;