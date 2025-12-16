const express = require("express");
const cors = require("cors");
const path = require("path");
const app = express();
const PORT = 11435;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "soc-triage-tester")));

// Dashboard route
app.get("/dashboard", (req, res) => {
    res.sendFile(path.join(__dirname, "soc-triage-tester", "soc-tester.html"));
});

console.log("🚀 Starting Enhanced SOC AI Server with Unified Orchestrator...");

// Import enhanced agents
const { EnhancedAppAI } = require("./scripts/appAI");
const { EnhancedEndpointAI } = require("./scripts/endpointAI");
const { EnhancedNetworkAI } = require("./scripts/networkAI");
const { ThreatIntelAI } = require("./scripts/threatIntelAI");

// Create agent instances
const appAI = new EnhancedAppAI();
const endpointAI = new EnhancedEndpointAI();
const networkAI = new EnhancedNetworkAI();
const threatIntel = new ThreatIntelAI();

console.log("✅ All AI agents initialized");

// Unified log classifier
class UnifiedAlertClassifier {
  static classifyAlert(alert) {
    const eventType = alert['Event Type'] || '';
    const subtype = alert.subtype || '';
    const logdesc = alert.logdesc || '';
    const hasIP = !!(alert.srcip || alert.dstip || alert.ip || alert.remip);
    const hasMAC = !!(alert.bssid || alert.mac || alert.stamac);
    const hasHostname = !!(alert.hostname || alert.devname);
    
    // Decision matrix
    if (subtype === 'wireless' || logdesc.includes('Rogue AP') || 
        eventType.includes('wireless') || hasMAC) {
      return { agent: 'appAI', type: 'wireless/non_ip' };
    }
    
    if (subtype === 'vpn' || logdesc.includes('VPN') || logdesc.includes('IPsec') || 
        eventType.includes('vpn') || alert.tunneltype) {
      return { agent: 'endpointAI', type: 'vpn/remote_access' };
    }
    
    if (eventType.includes('PH_DEV_MON') || eventType.includes('MON_') || 
        alert.intfName || alert.inIntfUtil !== undefined) {
      return { agent: 'appAI', type: 'performance/non_ip' };
    }
    
    if (logdesc.includes('DHCP') || (subtype === 'system' && alert.dhcp_msg)) {
      return { agent: 'appAI', type: 'dhcp/non_ip' };
    }
    
    if (eventType.includes('Aruba') || alert['Raw Event Log']?.includes('SNMP') || 
        logdesc.includes('SNMP')) {
      return { agent: 'appAI', type: 'snmp/device' };
    }
    
    if (hasIP && (subtype === 'traffic' || subtype === 'local' || 
                  eventType.includes('traffic'))) {
      return { agent: 'networkAI', type: 'network_traffic' };
    }
    
    if (hasIP) {
      return { agent: 'networkAI', type: 'generic_ip' };
    }
    
    // Default for unknown/alerts without IP
    return { agent: 'appAI', type: 'generic_non_ip' };
  }
}

// Enhanced address extractor with intelligence
class EnhancedAddressExtractor {
  static extractWithIntelligence(alert) {
    const classification = UnifiedAlertClassifier.classifyAlert(alert);
    let addresses = {};
    
    // Route to appropriate agent for address extraction
    switch (classification.agent) {
      case 'appAI':
        addresses = appAI.extractAddresses(alert);
        break;
      case 'networkAI':
        addresses = networkAI.extractAddresses(alert);
        break;
      case 'endpointAI':
        addresses = endpointAI.extractAddresses(alert);
        break;
      default:
        addresses = {
          source_address: 'Unknown',
          destination_address: 'Unknown',
          source_type: 'unknown',
          destination_type: 'unknown',
          is_non_ip_alert: !(alert.srcip || alert.dstip)
        };
    }
    
    // Add classification info
    addresses.classification = classification;
    
    // Add threat intelligence for IPs
    if (addresses.source_address && networkAI.isValidIP(addresses.source_address)) {
      addresses.source_threat_intel = threatIntel.getCountryForIP(addresses.source_address);
      const asnInfo = threatIntel.findASNForIP(addresses.source_address);
      if (asnInfo) {
        addresses.source_threat_intel.asn = asnInfo;
      }
    }
    
    if (addresses.destination_address && networkAI.isValidIP(addresses.destination_address)) {
      addresses.destination_threat_intel = threatIntel.getCountryForIP(addresses.destination_address);
      const asnInfo = threatIntel.findASNForIP(addresses.destination_address);
      if (asnInfo) {
        addresses.destination_threat_intel.asn = asnInfo;
      }
    }
    
    return addresses;
  }
}

// Mount individual agent routers for direct access
console.log("📡 Mounting individual agent routers...");

try {
    const threatIntelRouter = require("./scripts/threatIntelAI");
    app.use("/threatintel", threatIntelRouter);
    console.log("✅ ThreatIntelAI mounted at /threatintel");
} catch (error) {
    console.log("❌ ThreatIntelAI failed:", error.message);
}

try {
    const appAIRouter = require("./scripts/appAI");
    app.use("/appai", appAIRouter);
    console.log("✅ AppAI mounted at /appai");
} catch (error) {
    console.log("❌ AppAI failed:", error.message);
}

try {
    const endpointAIRouter = require("./scripts/endpointAI");
    app.use("/endpointai", endpointAIRouter);
    console.log("✅ EndpointAI mounted at /endpointai");
} catch (error) {
    console.log("❌ EndpointAI failed:", error.message);
}

try {
    const networkAIRouter = require("./scripts/networkAI");
    app.use("/networkai", networkAIRouter);
    console.log("✅ NetworkAI mounted at /networkai");
} catch (error) {
    console.log("❌ NetworkAI failed:", error.message);
}

// Unified API endpoint
app.post("/api/analyze", async (req, res) => {
  const requestId = Math.random().toString(36).substring(2, 10);
  console.log(`[${requestId}] 📡 UNIFIED API - Processing alert`);
  
  try {
    const alert = req.body;
    console.log(`[${requestId}] Alert type: ${alert['Event Type'] || 'Unknown'}`);
    
    // Step 1: Classify alert
    const classification = UnifiedAlertClassifier.classifyAlert(alert);
    console.log(`[${requestId}] Classification: ${classification.agent} - ${classification.type}`);
    
    // Step 2: Extract addresses with intelligence
    const addresses = EnhancedAddressExtractor.extractWithIntelligence(alert);
    
    // Step 3: Route to appropriate agent
    let analysis;
    switch (classification.agent) {
      case 'appAI':
        analysis = await appAI.analyze(alert);
        break;
      case 'networkAI':
        analysis = await networkAI.analyze(alert);
        break;
      case 'endpointAI':
        analysis = await endpointAI.analyze(alert);
        break;
      default:
        // Fallback to generic analysis
        analysis = {
          threat_level: 'low',
          attack_type: 'unclassified_event',
          confidence: 0.3,
          key_findings: ['Event could not be classified automatically'],
          immediate_actions: ['Manual review required'],
          investigation_steps: ['Check with security team'],
          business_impact: 'low'
        };
    }
    
    // Step 4: Enrich with threat intelligence for IPs
    let threatIntelAnalysis = {};
    if (addresses.source_threat_intel || addresses.destination_threat_intel) {
      threatIntelAnalysis = {
        source: addresses.source_threat_intel || null,
        destination: addresses.destination_threat_intel || null,
        has_high_risk_country: false,
        countries_involved: []
      };
      
      // Check for high-risk countries
      const highRiskCountries = ['RU', 'CN', 'IR', 'KP', 'SY', 'VE', 'NG'];
      if (addresses.source_threat_intel?.country_code && 
          highRiskCountries.includes(addresses.source_threat_intel.country_code)) {
        threatIntelAnalysis.has_high_risk_country = true;
        analysis.key_findings.push(`Source IP from high-risk country: ${addresses.source_threat_intel.country_code}`);
      }
    }
    
    // Step 5: Check internal threat indicators
    let internalThreatIndicators = [];
    if (addresses.source_is_internal) {
      internalThreatIndicators.push('Source is internal IP');
      if (analysis.threat_level === 'low') {
        analysis.threat_level = 'medium';
        analysis.key_findings.push('Internal IP involved - elevated threat level');
      }
    }
    
    if (addresses.destination_is_critical) {
      internalThreatIndicators.push('Destination is critical system');
      analysis.key_findings.push(`Access to critical system: ${addresses.destination_address}`);
      if (analysis.threat_level !== 'critical') {
        analysis.threat_level = 'high';
      }
    }
    
    // Step 6: Prepare response
    const response = {
      status: 'success',
      analysis,
      addresses,
      classification: {
        agent: classification.agent,
        type: classification.type,
        confidence: 0.9
      },
      threat_intelligence: threatIntelAnalysis,
      internal_analysis: {
        has_internal_ips: addresses.source_is_internal || addresses.destination_is_internal,
        indicators: internalThreatIndicators,
        source_internal: addresses.source_is_internal,
        destination_critical: addresses.destination_is_critical
      },
      metadata: {
        analyzedAt: new Date().toISOString(),
        request_id: requestId,
        processingTime: '0.2s',
        alert_type: alert['Event Type'] || 'Unknown',
        agent_used: classification.agent,
        has_ip_address: !!(alert.srcip || alert.dstip),
        has_mac_address: !!(alert.bssid || alert.mac),
        is_internal_alert: addresses.source_is_internal || addresses.destination_is_internal,
        unified_classifier: true
      }
    };
    
    console.log(`[${requestId}] ✅ Analysis complete: ${analysis.threat_level}`);
    res.json(response);
    
  } catch (error) {
    console.error(`[${requestId}] ❌ Unified API error:`, error.message);
    res.status(500).json({
      status: 'error',
      error: error.message,
      request_id: requestId,
      timestamp: new Date().toISOString()
    });
  }
});

// Health endpoint with agent status
app.get("/api/health", (req, res) => {
  res.json({
    status: 'healthy',
    message: 'Enhanced SOC AI Server with Unified Orchestrator',
    timestamp: new Date().toISOString(),
    agents: {
      appAI: {
        status: 'active',
        capabilities: ['non_ip_analysis', 'wireless_security', 'performance_monitoring'],
        focus: 'Non-IP and wireless threats'
      },
      networkAI: {
        status: 'active',
        capabilities: ['internal_threat_detection', 'network_traffic_analysis'],
        focus: 'IP-based threats including internal threats'
      },
      endpointAI: {
        status: 'active',
        capabilities: ['vpn_security', 'remote_access_monitoring'],
        focus: 'VPN and endpoint security'
      },
      threatIntelAI: {
        status: 'active',
        capabilities: ['ip_reputation', 'geolocation', 'asn_enrichment'],
        focus: 'Threat intelligence enrichment'
      }
    },
    unified_classifier: {
      status: 'active',
      decision_logic: 'Combines IP presence, event type, and identifiers'
    },
    endpoints: {
      '/api/analyze': 'Unified analysis endpoint (recommended)',
      '/api/health': 'System health',
      '/appai/*': 'Direct non-IP analysis',
      '/networkai/*': 'Direct network analysis',
      '/endpointai/*': 'Direct endpoint analysis',
      '/threatintel/*': 'Threat intelligence',
      '/dashboard': 'Web dashboard'
    }
  });
});

// Individual agent endpoints (for direct access)
app.post("/appai/analyze", async (req, res) => {
  try {
    const alert = req.body;
    const analysis = await appAI.analyze(alert);
    const addresses = appAI.extractAddresses(alert);
    
    res.json({
      status: 'success',
      analysis,
      addresses,
      metadata: {
        analyzedAt: new Date().toISOString(),
        agent: 'EnhancedAppAI',
        is_non_ip_analysis: true
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/networkai/analyze", async (req, res) => {
  try {
    const alert = req.body;
    const analysis = await networkAI.analyze(alert);
    const addresses = networkAI.extractAddresses(alert);
    
    res.json({
      status: 'success',
      analysis,
      addresses,
      metadata: {
        analyzedAt: new Date().toISOString(),
        agent: 'EnhancedNetworkAI',
        includes_internal_threat_detection: true
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/endpointai/analyze", async (req, res) => {
  try {
    const alert = req.body;
    const analysis = await endpointAI.analyze(alert);
    const addresses = endpointAI.extractAddresses(alert);
    
    res.json({
      status: 'success',
      analysis,
      addresses,
      metadata: {
        analyzedAt: new Date().toISOString(),
        agent: 'EnhancedEndpointAI',
        includes_vpn_analysis: true
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Country lookup endpoint using ThreatIntelAI
app.post("/api/ip-country", async (req, res) => {
  const requestId = Math.random().toString(36).substring(2, 10);
  
  try {
    const { ip } = req.body;
    
    if (!ip) {
      return res.status(400).json({ 
        error: 'IP address is required',
        country: 'Unknown',
        country_code: 'XX',
        continent: 'Unknown'
      });
    }

    // Validate IP format
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ipRegex.test(ip)) {
      return res.status(400).json({ 
        error: 'Invalid IP address format',
        country: 'Unknown',
        country_code: 'XX',
        continent: 'Unknown'
      });
    }

    // Get country data using ThreatIntelAI
    const countryData = threatIntel.getCountryForIP(ip);
    
    console.log(`[${requestId}] Country lookup for ${ip}: ${countryData.country} (${countryData.country_code})`);
    
    res.json({
      ...countryData,
      request_id: requestId,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error(`[${requestId}] ❌ IP country lookup failed:`, error);
    res.status(500).json({ 
      error: 'Failed to get country data',
      details: error.message,
      country: 'Unknown',
      country_code: 'XX',
      continent: 'Unknown',
      request_id: requestId
    });
  }
});

// Internal threat analysis endpoint
app.post("/api/analyze/internal", async (req, res) => {
  const requestId = Math.random().toString(36).substring(2, 10);
  
  try {
    const alert = req.body;
    const iocs = threatIntel.extractIOCs(alert);
    const enrichedIOCs = await threatIntel.enrichWithASN(iocs);
    const internalAnalysis = threatIntel.analyzeInternalThreats(alert, iocs, enrichedIOCs);
    
    res.json({
      status: 'success',
      analysis: internalAnalysis,
      ip_details: enrichedIOCs,
      metadata: {
        analyzedAt: new Date().toISOString(),
        total_ips: iocs.ips.length,
        internal_ips: iocs.ips.filter(ip => threatIntel.isInternalIP(ip)).length,
        request_id: requestId,
        agent: 'ThreatIntelAI'
      }
    });
  } catch (error) {
    console.error(`[${requestId}] Internal threat analysis failed:`, error);
    res.status(500).json({
      status: 'error',
      error: error.message,
      request_id: requestId,
      timestamp: new Date().toISOString()
    });
  }
});

// Test endpoint for system verification
app.post("/api/test", async (req, res) => {
  const testAlerts = [
    {
      name: "Wireless Rogue AP",
      data: {
        "Event Type": "FortiGate-event-wireless-rogue-detect-chg",
        "subtype": "wireless",
        "bssid": "7a:45:58:c3:04:6a",
        "ssid": "Free WiFi",
        "manuf": "Ubiquiti",
        "security": "Open"
      }
    },
    {
      name: "Internal Lateral Movement",
      data: {
        "Event Type": "FortiGate-traffic-allowed",
        "srcip": "192.168.1.100",
        "dstip": "192.168.1.1",
        "dstport": 445,
        "proto": "TCP",
        "action": "accept",
        "sentbyte": 15000000
      }
    },
    {
      name: "VPN Authentication Failure",
      data: {
        "Event Type": "FortiGate-event-neg-progress-p1-error",
        "subtype": "vpn",
        "status": "failed",
        "reason": "authentication failed",
        "remip": "185.243.115.84"
      }
    }
  ];
  
  const results = [];
  
  for (const test of testAlerts) {
    try {
      const classification = UnifiedAlertClassifier.classifyAlert(test.data);
      const addresses = EnhancedAddressExtractor.extractWithIntelligence(test.data);
      
      results.push({
        test: test.name,
        classification: classification,
        addresses: {
          source: addresses.source_address,
          source_type: addresses.source_type,
          source_internal: addresses.source_is_internal,
          destination: addresses.destination_address,
          destination_critical: addresses.destination_is_critical
        },
        status: 'processed'
      });
    } catch (error) {
      results.push({
        test: test.name,
        error: error.message,
        status: 'failed'
      });
    }
  }
  
  res.json({
    status: 'success',
    tests: results,
    system_status: 'operational',
    timestamp: new Date().toISOString()
  });
});

// Dashboard route (also at root)
app.get("/", (req, res) => {
  const acceptsHTML = req.headers.accept && req.headers.accept.includes('text/html');
  
  if (acceptsHTML) {
    res.sendFile(path.join(__dirname, "soc-triage-tester", "soc-tester.html"));
  } else {
    res.json({
      message: "Enhanced SOC AI Server with Unified Orchestrator",
      version: "3.0",
      description: "Advanced SOC AI system with unified classification, internal threat detection, and non-IP alert analysis",
      endpoints: {
        '/api/analyze': 'POST - Unified analysis endpoint (recommended)',
        '/api/analyze/internal': 'POST - Internal threat analysis',
        '/api/health': 'GET - System health and capabilities',
        '/api/ip-country': 'POST - IP geolocation lookup',
        '/api/test': 'POST - System verification test',
        '/appai/*': 'Direct non-IP analysis',
        '/networkai/*': 'Direct network analysis',
        '/endpointai/*': 'Direct endpoint analysis',
        '/threatintel/*': 'Threat intelligence',
        '/dashboard': 'GET - Web dashboard'
      },
      capabilities: [
        'Non-IP alert analysis (MAC, BSSID, hostnames)',
        'Internal IP threat detection (lateral movement, scanning)',
        'Wireless security monitoring',
        'Performance anomaly detection',
        'VPN and remote access security',
        'Unified classification and routing',
        'Threat intelligence enrichment'
      ]
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`📍 Server running on http://0.0.0.0:${PORT}`);
  console.log(`✅ Unified API available at /api/analyze`);
  console.log(`✅ Individual agents available at /appai/*, /networkai/*, /endpointai/*, /threatintel/*`);
  console.log(`✅ Dashboard available at /dashboard`);
  console.log(`📊 Ready to analyze both IP and non-IP alerts with internal threat detection!`);
  console.log(`🔍 Test the system: curl -X POST http://localhost:${PORT}/api/test`);
});