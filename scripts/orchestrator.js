const express = require('express');
const router = express.Router();

class SmartOrchestrator {
  constructor() {
    // Initialize all AI agents
    this.agents = {
      appAI: require('./appAI').EnhancedAppAI,
      endpointAI: require('./endpointAI').EnhancedEndpointAI,
      networkAI: require('./networkAI').EnhancedNetworkAI,
      threatIntelAI: require('./threatIntelAI').ThreatIntelAI
    };
    
    // Alert classification rules
    this.classificationRules = {
      // Wireless events
      'wireless': {
        patterns: ['wireless', 'rogue', 'bssid', 'ssid', 'signal', 'channel'],
        agent: 'appAI',
        priority: 'high'
      },
      
      // VPN events
      'vpn': {
        patterns: ['vpn', 'ipsec', 'ssl-alert', 'tunnel', 'remip', 'locip'],
        agent: 'endpointAI',
        priority: 'high'
      },
      
      // Performance monitoring
      'performance': {
        patterns: ['PH_DEV_MON', 'MON_', 'util', 'cpu', 'memory', 'disk'],
        agent: 'appAI',
        priority: 'low'
      },
      
      // DHCP events
      'dhcp': {
        patterns: ['dhcp', 'mac=', 'lease=', 'hostname='],
        agent: 'appAI',
        priority: 'medium'
      },
      
      // SNMP events
      'snmp': {
        patterns: ['snmp', 'trap', 'oid', 'mib', 'Aruba-'],
        agent: 'appAI',
        priority: 'medium'
      },
      
      // Network traffic
      'traffic': {
        patterns: ['traffic', 'srcip', 'dstip', 'port=', 'proto='],
        agent: 'networkAI',
        priority: 'high'
      },
      
      // Threat intelligence
      'threat_intel': {
        patterns: ['malicious', 'blacklist', 'known', 'abuse'],
        agent: 'threatIntelAI',
        priority: 'critical'
      }
    };
  }

  classifyAlert(alert) {
    const eventType = alert['Event Type'] || '';
    const subtype = alert.subtype || '';
    const logdesc = alert.logdesc || '';
    const rawLog = alert['Raw Event Log'] || '';
    const combinedText = `${eventType} ${subtype} ${logdesc} ${rawLog}`.toLowerCase();
    
    console.log(`🔍 ORCHESTRATOR - Classifying alert: ${eventType}`);
    
    // Check for specific patterns first
    for (const [category, rule] of Object.entries(this.classificationRules)) {
      for (const pattern of rule.patterns) {
        if (combinedText.includes(pattern.toLowerCase())) {
          console.log(`🔄 Matched pattern "${pattern}" -> Category: ${category}, Agent: ${rule.agent}`);
          return {
            agent: rule.agent,
            category: category,
            priority: rule.priority,
            matched_pattern: pattern
          };
        }
      }
    }
    
    // Check for IP addresses to determine if it's IP-based
    const hasPublicIP = this.hasPublicIP(alert);
    
    if (hasPublicIP) {
      console.log(`🌐 Contains public IP -> Using threatIntelAI`);
      return {
        agent: 'threatIntelAI',
        category: 'ip_based',
        priority: 'medium',
        matched_pattern: 'public_ip'
      };
    }
    
    // Default to AppAI for non-IP events
    console.log(`📱 No specific match -> Defaulting to AppAI`);
    return {
      agent: 'appAI',
      category: 'generic',
      priority: 'low',
      matched_pattern: 'default'
    };
  }

  hasPublicIP(alert) {
    const ipFields = ['srcip', 'dstip', 'src', 'dst', 'ip', 'source_ip', 'dest_ip', 
                     'client_ip', 'server_ip', 'remip', 'locip'];
    
    for (const field of ipFields) {
      if (alert[field] && this.isValidIP(alert[field])) {
        // Check if it's a public IP (not private/reserved)
        if (this.isPublicIP(alert[field])) {
          console.log(`✅ Found public IP in ${field}: ${alert[field]}`);
          return true;
        }
      }
    }
    
    // Check raw log
    if (alert['Raw Event Log']) {
      const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
      const ips = alert['Raw Event Log'].match(ipRegex) || [];
      
      for (const ip of ips) {
        if (this.isValidIP(ip) && this.isPublicIP(ip)) {
          console.log(`✅ Found public IP in raw log: ${ip}`);
          return true;
        }
      }
    }
    
    return false;
  }

  isPublicIP(ip) {
    if (!this.isValidIP(ip)) return false;
    
    // Private IP ranges
    const privateRanges = [
      '10.0.0.0/8',
      '172.16.0.0/12',
      '192.168.0.0/16',
      '127.0.0.0/8',
      '169.254.0.0/16',
      '224.0.0.0/4', // Multicast
      '240.0.0.0/4'  // Reserved
    ];
    
    const ipNum = this.ipToNumber(ip);
    
    for (const range of privateRanges) {
      const [network, prefix] = range.split('/');
      const prefixLength = parseInt(prefix);
      const networkNum = this.ipToNumber(network);
      const mask = (-1) << (32 - prefixLength);
      
      if ((ipNum & mask) === (networkNum & mask)) {
        return false;
      }
    }
    
    return true;
  }

  ipToNumber(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0);
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

  async routeToAgent(agentName, alert) {
    console.log(`🚀 Routing to ${agentName}...`);
    
    const AgentClass = this.agents[agentName];
    if (!AgentClass) {
      throw new Error(`Agent ${agentName} not found`);
    }
    
    const agent = new AgentClass();
    return await agent.analyze(alert);
  }

  async analyzeWithAllAgents(alert) {
    const results = {};
    const classification = this.classifyAlert(alert);
    
    // Always run the primary agent
    console.log(`🎯 Primary analysis with ${classification.agent}`);
    results.primary = await this.routeToAgent(classification.agent, alert);
    results.primary._agent = classification.agent;
    results.primary._category = classification.category;
    
    // For high priority alerts, run secondary analysis
    if (classification.priority === 'high' || classification.priority === 'critical') {
      console.log(`🔍 Secondary analysis for high priority alert`);
      
      // Choose a different agent for secondary analysis
      let secondaryAgent;
      if (classification.agent === 'appAI') {
        secondaryAgent = 'endpointAI';
      } else if (classification.agent === 'endpointAI') {
        secondaryAgent = 'networkAI';
      } else {
        secondaryAgent = 'appAI';
      }
      
      try {
        results.secondary = await this.routeToAgent(secondaryAgent, alert);
        results.secondary._agent = secondaryAgent;
        results.secondary._category = 'secondary_analysis';
      } catch (error) {
        console.error(`❌ Secondary analysis failed: ${error.message}`);
      }
    }
    
    return results;
  }

  consolidateResults(primaryResult, secondaryResult = null) {
    if (!secondaryResult) {
      return primaryResult;
    }
    
    // Compare and consolidate results
    const consolidated = { ...primaryResult };
    
    // Use higher threat level
    const primaryThreat = this.threatLevelToNumber(primaryResult.threat_level || 'low');
    const secondaryThreat = this.threatLevelToNumber(secondaryResult.threat_level || 'low');
    
    if (secondaryThreat > primaryThreat) {
      consolidated.threat_level = this.numberToThreatLevel(secondaryThreat);
      consolidated._consolidated = true;
      consolidated._original_threat = primaryResult.threat_level;
      consolidated._secondary_agent = secondaryResult._agent;
    }
    
    // Combine key findings
    if (secondaryResult.key_findings || secondaryResult.key_indicators) {
      const secondaryFindings = secondaryResult.key_findings || secondaryResult.key_indicators || [];
      const primaryFindings = primaryResult.key_findings || primaryResult.key_indicators || [];
      
      consolidated.key_findings = [...new Set([...primaryFindings, ...secondaryFindings])];
    }
    
    // Use higher confidence
    consolidated.confidence = Math.max(
      primaryResult.confidence || 0,
      secondaryResult.confidence || 0
    );
    
    return consolidated;
  }

  threatLevelToNumber(level) {
    const levels = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 };
    return levels[level.toLowerCase()] || 1;
  }

  numberToThreatLevel(num) {
    const levels = { 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' };
    return levels[num] || 'low';
  }
}

const orchestrator = new SmartOrchestrator();

// Express Routes
router.post('/analyze', async (req, res) => {
  const requestId = Math.random().toString(36).substring(2, 10);
  console.log(`[${requestId}] 🎯 SMART ORCHESTRATOR - Processing alert`);
  
  const startTime = Date.now();
  
  try {
    const alert = req.body;
    
    // Step 1: Classify the alert
    const classification = orchestrator.classifyAlert(alert);
    console.log(`[${requestId}] 📊 Classification:`, classification);
    
    // Step 2: Analyze with appropriate agent(s)
    const analysisResults = await orchestrator.analyzeWithAllAgents(alert);
    
    // Step 3: Consolidate results
    const consolidatedResult = orchestrator.consolidateResults(
      analysisResults.primary,
      analysisResults.secondary
    );
    
    const processingTime = Date.now() - startTime;
    
    // Step 4: Prepare response
    const response = {
      status: 'success',
      analysis: consolidatedResult,
      orchestration: {
        selected_agent: analysisResults.primary._agent,
        category: analysisResults.primary._category,
        priority: classification.priority,
        matched_pattern: classification.matched_pattern,
        secondary_analysis: !!analysisResults.secondary,
        consolidation: consolidatedResult._consolidated || false
      },
      metadata: {
        analyzedAt: new Date().toISOString(),
        processingTime: `${processingTime}ms`,
        request_id: requestId,
        agent: 'SmartOrchestrator',
        version: '2.0',
        classification_engine: 'rule_based'
      }
    };
    
    console.log(`[${requestId}] ✅ ORCHESTRATOR - Analysis complete in ${processingTime}ms`);
    console.log(`[${requestId}] 📈 Final threat level: ${consolidatedResult.threat_level || consolidatedResult.risk_score}`);
    
    res.json(response);
    
  } catch (error) {
    console.error(`[${requestId}] ❌ ORCHESTRATOR - Error:`, error.message);
    res.status(500).json({
      status: 'error',
      error: error.message,
      request_id: requestId,
      agent: 'SmartOrchestrator',
      timestamp: new Date().toISOString()
    });
  }
});

router.get('/health', async (req, res) => {
  const agentStatus = {};
  const agents = ['appAI', 'endpointAI', 'networkAI'];
  
  // Check each agent
  for (const agentName of agents) {
    try {
      const AgentClass = orchestrator.agents[agentName];
      const agent = new AgentClass();
      
      // Try to create an instance (basic health check)
      agentStatus[agentName] = {
        available: true,
        model: agent.model || 'unknown',
        ollama_available: agent.ollamaAvailable || false
      };
    } catch (error) {
      agentStatus[agentName] = {
        available: false,
        error: error.message
      };
    }
  }
  
  res.json({
    status: 'healthy',
    agent: 'SmartOrchestrator',
    version: '2.0',
    agents: agentStatus,
    classification_rules: Object.keys(orchestrator.classificationRules).length,
    capabilities: [
      'intelligent_alert_routing',
      'multi_agent_analysis',
      'result_consolidation',
      'priority_based_processing',
      'non_ip_alert_handling'
    ],
    timestamp: new Date().toISOString()
  });
});

router.get('/classify-test', (req, res) => {
  const testAlerts = [
    {
      name: 'Wireless Rogue AP',
      data: { 'Event Type': 'FortiGate-event-wireless-rogue-detect-chg', subtype: 'wireless', bssid: '7a:45:58:c3:04:6a' }
    },
    {
      name: 'VPN SSL Alert',
      data: { 'Event Type': 'FortiGate-event-ssl-vpn-session-alert', subtype: 'vpn', remip: '138.199.43.87' }
    },
    {
      name: 'Performance Monitoring',
      data: { 'Event Type': 'PH_DEV_MON_CPU_UTIL', intfName: 'port11' }
    },
    {
      name: 'Network Traffic',
      data: { 'Event Type': 'FortiGate-traffic-allowed', srcip: '172.31.27.236', dstip: '172.20.0.1' }
    },
    {
      name: 'DHCP Event',
      data: { 'Event Type': 'FortiGate-event-DHCP-response-Ack', mac: '78:AF:08:33:DF:A6' }
    }
  ];
  
  const results = testAlerts.map(test => ({
    alert_name: test.name,
    classification: orchestrator.classifyAlert(test.data)
  }));
  
  res.json({
    test_results: results,
    timestamp: new Date().toISOString()
  });
});

router.post('/classify', (req, res) => {
  const alert = req.body;
  const classification = orchestrator.classifyAlert(alert);
  
  res.json({
    classification,
    has_public_ip: orchestrator.hasPublicIP(alert),
    recommendations: {
      primary_agent: classification.agent,
      priority: classification.priority,
      expected_analysis_time: classification.priority === 'high' ? 'Fast (AI)' : 'Normal'
    }
  });
});

module.exports = router;
module.exports.SmartOrchestrator = SmartOrchestrator;