const express = require('express');
const router = express.Router();
const axios = require('axios');

class EnhancedNetworkAI {
  constructor() {
    this.ollamaAvailable = true;
    this.model = 'mistral:7b';
    
    // Enhanced threat intelligence with internal threat detection
    this.networkThreats = {
      // Known malicious IPs (external)
      known_malicious_ips: ['185.243.115.84', '45.77.80.133', '95.179.130.130'],
      
      // Suspicious ports
      suspicious_ports: [4444, 1337, 31337, 666, 6667, 8080, 8888, 9999],
      
      // Common C2 ports
      c2_ports: [443, 80, 53, 123, 161, 389, 636, 1433, 1521, 3306, 3389, 5432],
      
      // Data exfiltration ports
      data_exfiltration_ports: [21, 22, 25, 110, 143, 465, 587, 993, 995, 8443],
      
      // High-risk protocols
      high_risk_protocols: ['ICMP', 'UDP', 'GRE', 'ESP', 'AH'],
      
      // Internal threat detection rules
      internal_threat_indicators: {
        // Lateral movement patterns
        lateral_movement_ports: [445, 139, 135, 3389, 22, 23, 5985, 5986],
        
        // Data exfiltration patterns (internal to internal)
        data_exfiltration_sizes: {
          critical: 100000000, // 100MB
          high: 10000000,      // 10MB
          medium: 1000000      // 1MB
        },
        
        // Port scanning patterns
        scan_thresholds: {
          unique_ports: 10,
          unique_hosts: 5,
          time_window: 300 // 5 minutes
        },
        
        // Suspicious internal IP ranges
        suspicious_internal_ranges: [
          '169.254.', // APIPA
          '0.0.0.0',
          '255.255.255.255',
          '224.0.0.', // Multicast
          '239.255.255.' // Multicast
        ],
        
        // Critical internal systems (should have restricted access)
        critical_internal_systems: [
          'domaincontroller', 'ad', 'dc', 'sql', 'database',
          'fileserver', 'share', 'nas', 'backup',
          'management', 'admin', 'console', 'vcenter',
          'esxi', 'hyperv', 'firewall', 'router'
        ]
      }
    };
  }

  // Enhanced address extraction with internal IP classification
  extractAddresses(log) {
    console.log('🔍 ENHANCED NETWORKAI - Extracting addresses with internal classification');
    
    let source_address = 'Unknown';
    let destination_address = 'Unknown';
    let source_is_mac = false;
    let destination_is_mac = false;
    let source_is_internal = false;
    let destination_is_internal = false;
    let source_is_critical = false;
    let destination_is_critical = false;
    
    // Primary IP extraction
    if (log.srcip && log.srcip !== 'No IP' && this.isValidIP(log.srcip)) {
      source_address = log.srcip;
      source_is_internal = this.isInternalIP(log.srcip);
      source_is_critical = this.isCriticalSystem(log.srcip, log.src_hostname || '');
      console.log(`🌐 Found source IP: ${source_address} (Internal: ${source_is_internal}, Critical: ${source_is_critical})`);
    }
    
    if (log.dstip && log.dstip !== 'No IP' && this.isValidIP(log.dstip)) {
      destination_address = log.dstip;
      destination_is_internal = this.isInternalIP(log.dstip);
      destination_is_critical = this.isCriticalSystem(log.dstip, log.dst_hostname || '');
      console.log(`🌐 Found destination IP: ${destination_address} (Internal: ${destination_is_internal}, Critical: ${destination_is_critical})`);
    }
    
    // Alternative field names
    const sourceFields = ['src', 'source_ip', 'client_ip', 'source_address', 'remip'];
    const destFields = ['dst', 'dest_ip', 'server_ip', 'destination_address', 'locip'];
    
    for (const field of sourceFields) {
      if (log[field] && this.isValidIP(log[field]) && source_address === 'Unknown') {
        source_address = log[field];
        source_is_internal = this.isInternalIP(log[field]);
        console.log(`🌐 Found source in ${field}: ${source_address} (Internal: ${source_is_internal})`);
      }
    }
    
    for (const field of destFields) {
      if (log[field] && this.isValidIP(log[field]) && destination_address === 'Unknown') {
        destination_address = log[field];
        destination_is_internal = this.isInternalIP(log[field]);
        console.log(`🌐 Found destination in ${field}: ${destination_address} (Internal: ${destination_is_internal})`);
      }
    }
    
    // Check if either address is a critical system (by hostname)
    if (log.src_hostname && this.isCriticalSystem('', log.src_hostname)) {
      source_is_critical = true;
    }
    if (log.dst_hostname && this.isCriticalSystem('', log.dst_hostname)) {
      destination_is_critical = true;
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
      is_internal_to_internal: source_is_internal && destination_is_internal,
      is_external_to_internal: !source_is_internal && destination_is_internal,
      is_internal_to_external: source_is_internal && !destination_is_internal
    };
  }

  // Enhanced internal threat detection
  detectInternalThreats(alert, addresses) {
    const srcip = alert.srcip || 'Unknown';
    const dstip = alert.dstip || 'Unknown';
    const srcport = parseInt(alert.srcport || 0);
    const dstport = parseInt(alert.dstport || 0);
    const protocol = alert.proto || alert.protocol || 'Unknown';
    const action = alert.action || 'Unknown';
    const bytes_sent = parseInt(alert.sentbyte || alert.bytes_sent || 0);
    const bytes_received = parseInt(alert.rcvdbyte || alert.bytes_received || 0);
    const packets_sent = parseInt(alert.sentpkt || 0);
    const packets_received = parseInt(alert.rcvdpkt || 0);
    const duration = parseInt(alert.duration || 0);
    
    let internal_threats = [];
    let threat_score = 0;
    
    // 1. Internal lateral movement detection
    if (addresses.is_internal_to_internal) {
      // Check for lateral movement ports
      if (this.networkThreats.internal_threat_indicators.lateral_movement_ports.includes(dstport)) {
        internal_threats.push({
          type: 'lateral_movement',
          description: `Internal host ${srcip} accessing lateral movement port ${dstport}`,
          severity: 'high',
          score: 7
        });
        threat_score += 7;
      }
      
      // Check for access to critical systems
      if (addresses.destination_is_critical) {
        internal_threats.push({
          type: 'critical_system_access',
          description: `Internal host ${srcip} accessing critical system ${dstip}`,
          severity: 'high',
          score: 8
        });
        threat_score += 8;
      }
    }
    
    // 2. Internal data exfiltration
    if (addresses.is_internal_to_internal && bytes_sent > 0) {
      if (bytes_sent >= this.networkThreats.internal_threat_indicators.data_exfiltration_sizes.critical) {
        internal_threats.push({
          type: 'critical_data_exfiltration',
          description: `Large data transfer (${this.formatBytes(bytes_sent)}) between internal hosts`,
          severity: 'critical',
          score: 10
        });
        threat_score += 10;
      } else if (bytes_sent >= this.networkThreats.internal_threat_indicators.data_exfiltration_sizes.high) {
        internal_threats.push({
          type: 'high_data_exfiltration',
          description: `Significant data transfer (${this.formatBytes(bytes_sent)}) between internal hosts`,
          severity: 'high',
          score: 8
        });
        threat_score += 8;
      }
    }
    
    // 3. Internal port scanning detection
    if (action === 'client-rst' && duration < 10 && addresses.is_internal_to_internal) {
      internal_threats.push({
        type: 'internal_port_scan',
        description: `Internal host ${srcip} performing port scan (client reset after ${duration}s)`,
        severity: 'medium',
        score: 6
      });
      threat_score += 6;
    }
    
    // 4. Suspicious protocol usage internally
    if (addresses.is_internal_to_internal && this.networkThreats.high_risk_protocols.includes(protocol)) {
      internal_threats.push({
        type: 'suspicious_internal_protocol',
        description: `Suspicious protocol ${protocol} used between internal hosts`,
        severity: 'medium',
        score: 5
      });
        threat_score += 5;
    }
    
    // 5. Unusual internal traffic patterns
    if (addresses.is_internal_to_internal) {
      // Asymmetric traffic (one-way)
      if ((bytes_sent > 0 && bytes_received === 0) || (bytes_sent === 0 && bytes_received > 0)) {
        internal_threats.push({
          type: 'asymmetric_internal_traffic',
          description: 'One-way traffic between internal hosts',
          severity: 'medium',
          score: 4
        });
        threat_score += 4;
      }
      
      // High packet count with small duration (potential scan)
      if (packets_sent > 100 && duration < 30) {
        internal_threats.push({
          type: 'rapid_internal_scan',
          description: `Rapid packet burst (${packets_sent} packets in ${duration}s)`,
          severity: 'medium',
          score: 5
        });
        threat_score += 5;
      }
    }
    
    // 6. Access from non-standard internal ranges
    if (addresses.source_is_internal && this.isSuspiciousInternalIP(srcip)) {
      internal_threats.push({
        type: 'suspicious_internal_source',
        description: `Traffic from suspicious internal IP range: ${srcip}`,
        severity: 'medium',
        score: 6
      });
      threat_score += 6;
    }
    
    return {
      has_internal_threats: internal_threats.length > 0,
      internal_threats,
      internal_threat_score: threat_score,
      internal_threat_level: this.getThreatLevelFromScore(threat_score)
    };
  }

  // Main analysis with internal threat detection
  assessNetworkTrafficRisk(alert) {
    const addresses = this.extractAddresses(alert);
    const internalAnalysis = this.detectInternalThreats(alert, addresses);
    
    const srcip = alert.srcip || 'Unknown';
    const dstip = alert.dstip || 'Unknown';
    const srcport = parseInt(alert.srcport || 0);
    const dstport = parseInt(alert.dstport || 0);
    const protocol = alert.proto || alert.protocol || 'Unknown';
    const action = alert.action || 'Unknown';
    const bytes_sent = parseInt(alert.sentbyte || alert.bytes_sent || 0);
    const bytes_received = parseInt(alert.rcvdbyte || alert.bytes_received || 0);
    const duration = parseInt(alert.duration || 0);
    
    let risk_score = 5;
    let threat_type = "network_traffic";
    let confidence = 0.5;
    let key_indicators = [];
    let immediate_actions = ["Monitor network traffic"];
    let investigation_steps = ["Review firewall rules"];
    let business_impact = 'low';
    
    // Start with internal threat score
    risk_score = Math.max(risk_score, internalAnalysis.internal_threat_score);
    
    // Add internal threat findings
    if (internalAnalysis.has_internal_threats) {
      threat_type = "internal_network_threat";
      confidence = Math.max(confidence, 0.7);
      
      internalAnalysis.internal_threats.forEach(threat => {
        key_indicators.push(`${threat.severity.toUpperCase()}: ${threat.description}`);
      });
      
      // Add specific actions for internal threats
      if (internalAnalysis.internal_threat_level === 'critical' || internalAnalysis.internal_threat_level === 'high') {
        immediate_actions = [
          'IMMEDIATE: Investigate internal host',
          'Check for compromised credentials',
          'Review access patterns'
        ];
        business_impact = 'high';
      }
    }
    
    // External threat detection (existing logic)
    if (this.networkThreats.known_malicious_ips.includes(srcip) || 
        this.networkThreats.known_malicious_ips.includes(dstip)) {
      risk_score = Math.max(risk_score, 9);
      threat_type = "known_malicious_ip";
      confidence = Math.max(confidence, 0.9);
      key_indicators.push(`🚨 KNOWN MALICIOUS IP: ${srcip}`);
      immediate_actions = ["BLOCK IP immediately", "Investigate source system"];
      business_impact = 'critical';
    }
    
    if (this.networkThreats.suspicious_ports.includes(dstport) || 
        this.networkThreats.suspicious_ports.includes(srcport)) {
      risk_score = Math.max(risk_score, 8);
      threat_type = "suspicious_port_activity";
      confidence = Math.max(confidence, 0.8);
      key_indicators.push(`Suspicious port usage: ${dstport}`);
      immediate_actions.push("Investigate port usage");
    }
    
    if (bytes_sent > 10000000) {
      risk_score = Math.max(risk_score, 8);
      threat_type = "potential_data_exfiltration";
      confidence = Math.max(confidence, 0.7);
      key_indicators.push(`Large outbound data: ${this.formatBytes(bytes_sent)}`);
      immediate_actions.push("Investigate data transfer");
    }
    
    // Determine overall threat level
    let threat_level = 'low';
    if (risk_score >= 9) threat_level = 'critical';
    else if (risk_score >= 7) threat_level = 'high';
    else if (risk_score >= 5) threat_level = 'medium';
    
    return {
      threat_level,
      attack_type: threat_type,
      risk_score,
      confidence,
      key_indicators,
      immediate_actions,
      investigation_steps,
      business_impact,
      traffic_analysis: {
        source_ip: srcip,
        destination_ip: dstip,
        source_port: srcport,
        destination_port: dstport,
        protocol: this.protocolNumberToName(protocol),
        bytes_sent,
        bytes_received,
        duration_seconds: duration,
        action,
        addresses: {
          source_is_internal: addresses.source_is_internal,
          destination_is_internal: addresses.destination_is_internal,
          source_is_critical: addresses.source_is_critical,
          destination_is_critical: addresses.destination_is_critical
        }
      },
      internal_threat_analysis: internalAnalysis
    };
  }

  // Helper methods
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

  isCriticalSystem(ip, hostname) {
    if (!hostname) hostname = '';
    
    // Check by hostname
    const lowerHostname = hostname.toLowerCase();
    const isCriticalByName = this.networkThreats.internal_threat_indicators.critical_internal_systems
      .some(system => lowerHostname.includes(system));
    
    // Check by IP (could add specific critical IPs)
    const criticalIPs = [
      '192.168.1.1', '192.168.1.254', '10.0.0.1', '10.0.0.254',
      '172.16.0.1', '172.16.0.254'
    ];
    
    const isCriticalByIP = criticalIPs.includes(ip);
    
    return isCriticalByName || isCriticalByIP;
  }

  isSuspiciousInternalIP(ip) {
    if (!ip) return false;
    
    return this.networkThreats.internal_threat_indicators.suspicious_internal_ranges
      .some(range => ip.startsWith(range));
  }

  getThreatLevelFromScore(score) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 5) return 'medium';
    return 'low';
  }

  protocolNumberToName(proto) {
    const protocols = {
      '1': 'ICMP', '6': 'TCP', '17': 'UDP', '47': 'GRE',
      '50': 'ESP', '51': 'AH', 'ICMP': 'ICMP',
      'TCP': 'TCP', 'UDP': 'UDP'
    };
    return protocols[proto] || proto;
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

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

  async analyze(alert) {
    console.log('🔍 ENHANCED NETWORKAI - Analyzing network alert');
    
    const analysis = this.assessNetworkTrafficRisk(alert);
    
    // Add metadata
    analysis._analyzed_by = 'EnhancedNetworkAI';
    analysis._analysis_method = 'rule_based';
    analysis._timestamp = new Date().toISOString();
    
    return analysis;
  }
}

const enhancedNetworkAI = new EnhancedNetworkAI();

// Express Routes
router.post('/analyze', async (req, res) => {
  const requestId = Math.random().toString(36).substring(2, 10);
  console.log(`[${requestId}] 📡 ENHANCED NETWORKAI - Processing request`);
  
  try {
    const alert = req.body;
    const analysis = await enhancedNetworkAI.analyze(alert);
    
    const response = {
      status: 'success',
      analysis,
      metadata: {
        analyzedAt: new Date().toISOString(),
        agent: 'EnhancedNetworkAI',
        processingTime: '0.1s',
        request_id: requestId,
        capabilities: [
          'internal_threat_detection',
          'lateral_movement_detection',
          'data_exfiltration_detection',
          'port_scanning_detection',
          'external_threat_detection'
        ]
      }
    };
    
    console.log(`[${requestId}] ✅ ENHANCED NETWORKAI - Analysis complete: ${analysis.threat_level}`);
    res.json(response);
    
  } catch (error) {
    console.error(`[${requestId}] ❌ ENHANCED NETWORKAI - Error:`, error.message);
    res.status(500).json({
      status: 'error',
      error: error.message,
      request_id: requestId,
      agent: 'EnhancedNetworkAI'
    });
  }
});

router.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    agent: 'EnhancedNetworkAI',
    version: '3.0',
    capabilities: [
      'internal_ip_threat_detection',
      'lateral_movement_analysis',
      'critical_system_monitoring',
      'data_exfiltration_detection',
      'port_scanning_detection'
    ],
    internal_threat_detection: {
      enabled: true,
      lateral_movement_ports: enhancedNetworkAI.networkThreats.internal_threat_indicators.lateral_movement_ports,
      data_exfiltration_thresholds: enhancedNetworkAI.networkThreats.internal_threat_indicators.data_exfiltration_sizes,
      critical_system_indicators: enhancedNetworkAI.networkThreats.internal_threat_indicators.critical_internal_systems
    },
    timestamp: new Date().toISOString()
  });
});

module.exports = router;
module.exports.EnhancedNetworkAI = EnhancedNetworkAI;