const express = require('express');
const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');
const { Reader } = require('@maxmind/geoip2-node');
const router = express.Router();

class ThreatIntelAI {
  constructor() {
    this.knownThreats = {
      malicious_ips: [],
      malicious_domains: ['evil-domain.com', 'malware-distribution.net'],
      // Internal threat indicators
      suspicious_internal_patterns: [],
      critical_internal_systems: []
    };
    this.asnDatabaseV4 = new Map();
    this.asnDatabaseV6 = new Map();
    this.countryReader = null;
    
    this.loadBlacklist();
    this.loadASNDatabases();
    this.loadCountryDatabase();
    this.loadInternalThreatPatterns();
  }

  async loadCountryDatabase() {
    try {
      const countryDbPath = path.join(__dirname, '..', 'GeoLite2-Country.mmdb');
      console.log('🌍 Loading Country MMDB database from:', countryDbPath);
      
      if (fs.existsSync(countryDbPath)) {
        this.countryReader = await Reader.open(countryDbPath);
        console.log('✅ Country MMDB database loaded successfully');
        
        // Test the database
        try {
          const testResponse = this.countryReader.country('1.1.1.1');
          console.log('🧪 Country DB test - 1.1.1.1 →', testResponse.country?.isoCode || 'Unknown');
        } catch (testError) {
          console.log('⚠️ Country DB test failed (may be expected):', testError.message);
        }
      } else {
        console.warn('⚠️ GeoLite2-Country.mmdb not found at:', countryDbPath);
      }
    } catch (error) {
      console.error('❌ Error loading country database:', error);
    }
  }

  // Load internal threat patterns from file
  loadInternalThreatPatterns() {
    try {
      const patternsPath = path.join(__dirname, '..', 'internal-threat-patterns.json');
      console.log('🔍 Looking for internal threat patterns at:', patternsPath);
      
      if (fs.existsSync(patternsPath)) {
        const data = JSON.parse(fs.readFileSync(patternsPath, 'utf8'));
        this.knownThreats.suspicious_internal_patterns = data.suspicious_patterns || [];
        this.knownThreats.critical_internal_systems = data.critical_systems || [];
        console.log(`✅ Loaded ${this.knownThreats.suspicious_internal_patterns.length} internal threat patterns`);
        console.log(`✅ Loaded ${this.knownThreats.critical_internal_systems.length} critical systems`);
      } else {
        console.log('⚠️ No internal threat patterns file found, using defaults');
        // Default patterns
        this.knownThreats.suspicious_internal_patterns = [
          { type: 'internal_scan', pattern: 'src_internal:true AND dst_internal:true AND port_count:>10', severity: 'high' },
          { type: 'critical_system_access', pattern: 'dst_hostname:contains("dc") OR dst_hostname:contains("sql")', severity: 'high' },
          { type: 'data_exfiltration', pattern: 'src_internal:true AND bytes_sent:>10000000', severity: 'critical' }
        ];
        this.knownThreats.critical_internal_systems = [
          { ip: '192.168.1.1', hostname: 'gateway', type: 'network', criticality: 'high' },
          { ip: '192.168.1.100', hostname: 'dc01', type: 'domain_controller', criticality: 'critical' },
          { ip: '192.168.1.150', hostname: 'sql01', type: 'database', criticality: 'critical' }
        ];
      }
    } catch (error) {
      console.error('❌ Error loading internal threat patterns:', error);
    }
  }

  getCountryForIP(ip) {
    if (!this.countryReader) {
      return { 
        country: 'Unknown', 
        country_code: 'XX',
        continent: 'Unknown',
        error: 'Country database not loaded'
      };
    }

    // Check if IP is internal first
    if (this.isInternalIP(ip)) {
      return {
        country: 'Internal Network',
        country_code: 'INT',
        continent: 'Private',
        is_internal: true,
        network_type: 'private'
      };
    }

    try {
      const response = this.countryReader.country(ip);
      
      return {
        country: response.country?.names?.en || 'Unknown',
        country_code: response.country?.isoCode || 'XX',
        continent: response.continent?.names?.en || 'Unknown',
        continent_code: response.continent?.code || 'XX',
        is_in_european_union: response.country?.isInEuropeanUnion || false,
        accuracy_radius: response.country?.confidence || 0,
        is_internal: false,
        network_type: 'public'
      };
    } catch (error) {
      console.log(`❌ Country lookup failed for ${ip}:`, error.message);
      return {
        country: 'Unknown',
        country_code: 'XX',
        continent: 'Unknown',
        error: error.message
      };
    }
  }

  async loadASNDatabases() {
    try {
      console.log('🌍 Loading ASN databases...');
      
      const asnV4Path = path.join(__dirname, '..', 'GeoLite2-ASN-Blocks-IPv4.csv');
      if (fs.existsSync(asnV4Path)) {
        await this.loadASNFromCSV(asnV4Path, this.asnDatabaseV4);
        console.log(`✅ Loaded ${this.asnDatabaseV4.size} IPv4 ASN records`);
      } else {
        console.warn('⚠️ GeoLite2-ASN-Blocks-IPv4.csv not found');
      }

      const asnV6Path = path.join(__dirname, '..', 'GeoLite2-ASN-Blocks-IPv6.csv');
      if (fs.existsSync(asnV6Path)) {
        await this.loadASNFromCSV(asnV6Path, this.asnDatabaseV6);
        console.log(`✅ Loaded ${this.asnDatabaseV6.size} IPv6 ASN records`);
      } else {
        console.warn('⚠️ GeoLite2-ASN-Blocks-IPv6.csv not found');
      }

    } catch (error) {
      console.error('❌ Error loading ASN databases:', error);
    }
  }

  loadASNFromCSV(filePath, database) {
    return new Promise((resolve, reject) => {
      fs.createReadStream(filePath)
        .pipe(csv({ 
          headers: ['network', 'autonomous_system_number', 'autonomous_system_organization'],
          skipEmptyLines: true 
        }))
        .on('data', (row) => {
          if (row.network && row.autonomous_system_organization) {
            database.set(row.network, {
              asn: row.autonomous_system_number || 'Unknown',
              organization: row.autonomous_system_organization
            });
          }
        })
        .on('end', () => resolve())
        .on('error', reject);
    });
  }

  findASNForIP(ip) {
    // Check if internal IP first
    if (this.isInternalIP(ip)) {
      return {
        cidr: 'N/A',
        asn: 'N/A',
        organization: 'Internal Network',
        is_internal: true,
        network_type: 'private'
      };
    }

    const ipNum = this.ipToNumber(ip);
    const database = ip.includes(':') ? this.asnDatabaseV6 : this.asnDatabaseV4;
    
    let bestMatch = null;
    
    for (const [cidr, asnInfo] of database) {
      if (this.isIPInCIDR(ip, cidr)) {
        if (!bestMatch || this.getCIDRMask(cidr) > this.getCIDRMask(bestMatch.cidr)) {
          bestMatch = { cidr, ...asnInfo };
        }
      }
    }
    
    if (bestMatch) {
      bestMatch.is_internal = false;
      bestMatch.network_type = 'public';
    }
    
    return bestMatch;
  }

  ipToNumber(ip) {
    if (ip.includes(':')) {
      return BigInt('0x' + ip.split(':').join(''));
    } else {
      return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0);
    }
  }

  isIPInCIDR(ip, cidr) {
    const [network, prefix] = cidr.split('/');
    const prefixLength = parseInt(prefix);
    
    const ipNum = this.ipToNumber(ip);
    const networkNum = this.ipToNumber(network);
    const mask = this.getMask(prefixLength, ip.includes(':'));
    
    return (ipNum & mask) === (networkNum & mask);
  }

  getMask(prefixLength, isIPv6 = false) {
    if (isIPv6) {
      return BigInt(-1) << BigInt(128 - prefixLength);
    } else {
      return (-1) << (32 - prefixLength);
    }
  }

  getCIDRMask(cidr) {
    return parseInt(cidr.split('/')[1]);
  }

  loadBlacklist() {
    try {
      const blacklistPath = path.join(__dirname, '..', 'blacklist.txt');
      console.log(`Looking for blacklist at: ${blacklistPath}`);
      
      if (fs.existsSync(blacklistPath)) {
        const data = fs.readFileSync(blacklistPath, 'utf8');
        this.knownThreats.malicious_ips = data
          .split('\n')
          .map(ip => ip.trim())
          .filter(ip => ip && !ip.startsWith('#') && this.isValidIP(ip));
        
        console.log(`✅ Loaded ${this.knownThreats.malicious_ips.length} IPs from blacklist.txt`);
      } else {
        console.warn('⚠️ blacklist.txt not found');
        this.knownThreats.malicious_ips = ['185.243.115.84', '45.77.80.133', '95.179.130.130'];
      }
    } catch (error) {
      console.error('❌ Error loading blacklist:', error);
      this.knownThreats.malicious_ips = ['185.243.115.84', '45.77.80.133', '95.179.130.130'];
    }
  }

  async analyzeThreat(req, res) {
    console.log('🔍 ThreatIntelAI analyzing with ASN, Country, and Internal Threat data...');
    
    try {
      const alertData = req.body;
      console.log('Received alert:', alertData['Event Type'] || 'Unknown');
      
      const iocs = this.extractIOCs(alertData);
      const enrichedIOCs = await this.enrichWithASN(iocs);
      const analysis = this.analyzeIOCs(iocs, enrichedIOCs);
      
      // Create country summary
      const countrySummary = {};
      Object.values(enrichedIOCs).forEach(data => {
        if (data.country_code !== 'XX') {
          if (!countrySummary[data.country_code]) {
            countrySummary[data.country_code] = {
              country: data.country,
              count: 0,
              risk_level: data.risk_level,
              organizations: new Set()
            };
          }
          countrySummary[data.country_code].count++;
          countrySummary[data.country_code].organizations.add(data.organization);
        }
      });

      // Internal threat analysis
      const internalAnalysis = this.analyzeInternalThreats(alertData, iocs, enrichedIOCs);

      const result = {
        status: 'analyzed',
        verdict: analysis.verdict,
        confidence: analysis.confidence,
        severity: analysis.severity,
        matched_iocs: analysis.matched_iocs,
        reasons: analysis.reasons,
        recommended_actions: analysis.recommended_actions,
        
        // Enhanced location data
        geographical_analysis: {
          countries_involved: Object.keys(countrySummary).length,
          country_summary: Object.entries(countrySummary).map(([code, info]) => ({
            country_code: code,
            country: info.country,
            ip_count: info.count,
            risk_level: info.risk_level,
            organizations: Array.from(info.organizations)
          })),
          detailed_ip_data: enrichedIOCs
        },
        
        // Internal threat analysis
        internal_threat_analysis: {
          has_internal_ips: iocs.ips.some(ip => this.isInternalIP(ip)),
          internal_ip_count: iocs.ips.filter(ip => this.isInternalIP(ip)).length,
          critical_systems_involved: internalAnalysis.critical_systems,
          suspicious_internal_patterns: internalAnalysis.suspicious_patterns,
          internal_threat_score: internalAnalysis.threat_score,
          internal_threat_level: internalAnalysis.threat_level
        },
        
        metadata: {
          analyzedAt: new Date().toISOString(),
          total_ips_analyzed: iocs.ips.length,
          internal_ips_analyzed: iocs.ips.filter(ip => this.isInternalIP(ip)).length,
          blacklist_source: 'file',
          asn_enrichment: true,
          country_enrichment: true,
          internal_threat_detection: true,
          agent: 'ThreatIntelAI'
        }
      };
      
      console.log('✅ ThreatIntelAI complete:', result.verdict);
      res.json(result);
      
    } catch (error) {
      console.error('ThreatIntelAI error:', error);
      res.status(500).json({
        status: 'error',
        error: error.message,
        timestamp: new Date().toISOString(),
        agent: 'ThreatIntelAI'
      });
    }
  }

  async enrichWithASN(iocs) {
    const enriched = {};
    
    for (const ip of iocs.ips) {
      const asnInfo = this.findASNForIP(ip);
      const countryInfo = this.getCountryForIP(ip);
      const isInternal = this.isInternalIP(ip);
      const isCritical = this.isCriticalSystem(ip, '');
      
      enriched[ip] = {
        ip: ip,
        asn: asnInfo ? asnInfo.asn : 'Unknown',
        organization: asnInfo ? asnInfo.organization : 'Unknown',
        country: countryInfo.country,
        country_code: countryInfo.country_code,
        continent: countryInfo.continent,
        continent_code: countryInfo.continent_code,
        risk_level: this.assessGeoRisk(countryInfo, asnInfo),
        accuracy_radius: countryInfo.accuracy_radius,
        is_internal: isInternal,
        is_critical_system: isCritical,
        network_type: isInternal ? 'private' : 'public'
      };
    }
    
    return enriched;
  }

  // Analyze internal threats
  analyzeInternalThreats(alert, iocs, enrichedIOCs) {
    const internalIPs = iocs.ips.filter(ip => this.isInternalIP(ip));
    let threat_score = 0;
    let critical_systems = [];
    let suspicious_patterns = [];
    
    // Check for internal IPs accessing critical systems
    for (const ip of internalIPs) {
      const ipData = enrichedIOCs[ip];
      
      // Check if this is a critical system
      if (ipData?.is_critical_system) {
        critical_systems.push({
          ip: ip,
          type: 'critical_system',
          risk: 'high'
        });
        threat_score += 8;
      }
      
      // Check for suspicious internal patterns
      const patterns = this.detectInternalPatterns(alert, ip);
      if (patterns.length > 0) {
        suspicious_patterns.push(...patterns);
        threat_score += patterns.length * 5;
      }
    }
    
    // Check for internal to internal communication with large data transfer
    if (alert.sentbyte && parseInt(alert.sentbyte) > 10000000) {
      if (iocs.ips.some(ip => this.isInternalIP(ip))) {
        suspicious_patterns.push({
          type: 'internal_data_exfiltration',
          description: `Large data transfer (${alert.sentbyte} bytes) involving internal IPs`,
          risk: 'high'
        });
        threat_score += 10;
      }
    }
    
    // Determine threat level
    let threat_level = 'low';
    if (threat_score >= 15) threat_level = 'critical';
    else if (threat_score >= 10) threat_level = 'high';
    else if (threat_score >= 5) threat_level = 'medium';
    
    return {
      threat_score,
      threat_level,
      critical_systems,
      suspicious_patterns,
      has_internal_threats: threat_score > 0
    };
  }

  // Detect suspicious internal patterns
  detectInternalPatterns(alert, ip) {
    const patterns = [];
    
    // Pattern 1: Internal scanning (multiple ports)
    if (alert.dstport && alert.srcip === ip) {
      // Check if this is part of a scan pattern
      patterns.push({
        type: 'potential_internal_scan',
        description: `Internal IP ${ip} scanning port ${alert.dstport}`,
        risk: 'medium'
      });
    }
    
    // Pattern 2: Access to known critical ports from internal IPs
    const criticalPorts = [445, 3389, 22, 23, 135, 139];
    if (alert.dstport && criticalPorts.includes(parseInt(alert.dstport))) {
      patterns.push({
        type: 'critical_port_access',
        description: `Internal IP ${ip} accessing critical port ${alert.dstport}`,
        risk: 'high'
      });
    }
    
    // Pattern 3: High volume traffic from internal IP
    if (alert.sentbyte && parseInt(alert.sentbyte) > 5000000) {
      patterns.push({
        type: 'high_volume_internal_traffic',
        description: `Internal IP ${ip} sending ${alert.sentbyte} bytes`,
        risk: 'medium'
      });
    }
    
    return patterns;
  }

  assessGeoRisk(countryInfo, asnInfo) {
    // Internal IPs get low risk (unless they're in blacklist, handled elsewhere)
    if (countryInfo.is_internal) {
      return 'low';
    }
    
    const highRiskCountries = ['RU', 'CN', 'KP', 'IR', 'SY', 'VE'];
    const mediumRiskCountries = ['BR', 'IN', 'VN', 'UA', 'TR', 'PK', 'NG'];
    
    const highRiskOrgs = ['TOR', 'PROXY', 'VPN', 'Hosting', 'Bulletproof'];
    const mediumRiskOrgs = ['ISP', 'Telecom', 'Mobile'];
    
    let riskLevel = 'low';
    const org = asnInfo?.organization?.toUpperCase() || '';
    
    if (highRiskCountries.includes(countryInfo.country_code)) {
      riskLevel = 'high';
    } else if (mediumRiskCountries.includes(countryInfo.country_code)) {
      riskLevel = 'medium';
    }
    
    if (highRiskOrgs.some(riskOrg => org.includes(riskOrg.toUpperCase()))) {
      riskLevel = riskLevel === 'low' ? 'high' : riskLevel;
    } else if (mediumRiskOrgs.some(riskOrg => org.includes(riskOrg.toUpperCase()))) {
      riskLevel = riskLevel === 'low' ? 'medium' : riskLevel;
    }
    
    return riskLevel;
  }

  analyzeIOCs(iocs, enrichedIOCs = {}) {
    let confidence = 0;
    let verdict = 'benign';
    let severity = 'low';
    const matched_iocs = [];
    const reasons = [];
    const recommended_actions = [];

    // First, show country information for every IP
    for (const ip of iocs.ips) {
      if (enrichedIOCs[ip]) {
        const geoData = enrichedIOCs[ip];
        
        // Always show country information for every IP
        if (geoData.country !== 'Unknown') {
          reasons.push(`📍 ${ip} originated from ${geoData.country} (${geoData.country_code}) - ${geoData.organization}`);
        } else {
          reasons.push(`📍 ${ip} - Country: Unknown - ${geoData.organization}`);
        }
        
        // Highlight internal IPs
        if (geoData.is_internal) {
          reasons.push(`   🏠 INTERNAL IP detected (${geoData.network_type} network)`);
          
          // Check if it's a critical system
          if (geoData.is_critical_system) {
            reasons.push(`   ⚠️ CRITICAL SYSTEM: ${ip} is identified as critical infrastructure`);
            matched_iocs.push(`critical_system:${ip}`);
            confidence = Math.max(confidence, 0.7);
            verdict = 'suspicious';
            severity = 'high';
            recommended_actions.push('Monitor access to critical system');
          }
        }
      }

      // Check for malicious IPs (blacklist)
      if (this.knownThreats.malicious_ips.includes(ip)) {
        matched_iocs.push(`malicious_ip:${ip}`);
        confidence = Math.max(confidence, 0.8);
        verdict = 'malicious';
        severity = 'high';
        reasons.push(`🚨 KNOWN MALICIOUS IP: ${ip} (from blacklist)`);
        recommended_actions.push('IMMEDIATE: Block IP at firewall');
      }

      // Add risk-based reasoning
      if (enrichedIOCs[ip]) {
        const geoData = enrichedIOCs[ip];
        if (geoData.risk_level === 'high') {
          reasons.push(`⚠️ HIGH RISK: ${ip} from ${geoData.country} belongs to ${geoData.organization}`);
          confidence = Math.max(confidence, 0.7);
          if (verdict !== 'malicious') {
            verdict = 'suspicious';
            severity = 'medium';
          }
          recommended_actions.push('Investigate traffic from high-risk country');
        } else if (geoData.risk_level === 'medium') {
          reasons.push(`ℹ️ MEDIUM RISK: ${ip} from ${geoData.country} - ${geoData.organization}`);
          confidence = Math.max(confidence, 0.5);
          if (verdict === 'benign') {
            verdict = 'suspicious';
            severity = 'low';
          }
        }
      }
    }

    // Domain checks
    for (const domain of iocs.domains) {
      if (this.knownThreats.malicious_domains.includes(domain)) {
        matched_iocs.push(`malicious_domain:${domain}`);
        confidence = Math.max(confidence, 0.9);
        verdict = 'malicious';
        severity = 'high';
        reasons.push(`🚨 KNOWN MALICIOUS DOMAIN: ${domain}`);
        recommended_actions.push('IMMEDIATE: Block domain at DNS/web proxy');
      }
    }

    // Summary based on findings
    if (matched_iocs.length === 0) {
      if (iocs.ips.length > 0) {
        // Check if we have any high-risk countries
        const highRiskIPs = Object.values(enrichedIOCs).filter(data => data.risk_level === 'high');
        if (highRiskIPs.length > 0) {
          reasons.push(`🔍 No direct threats detected, but ${highRiskIPs.length} IP(s) from high-risk countries`);
        } else {
          const internalIPs = iocs.ips.filter(ip => this.isInternalIP(ip));
          if (internalIPs.length > 0) {
            reasons.push(`🏠 ${internalIPs.length} internal IP(s) detected - monitoring internal traffic`);
          } else {
            reasons.push('✅ No known threats detected in blacklist');
          }
        }
      } else {
        reasons.push('ℹ️ No IP addresses found to analyze');
      }
      recommended_actions.push('Continue monitoring');
    } else {
      reasons.push(`🎯 ${matched_iocs.length} direct threat(s) identified`);
    }

    return {
      verdict,
      confidence,
      severity,
      matched_iocs,
      reasons,
      recommended_actions
    };
  }

  extractIOCs(alertData) {
    const iocs = { ips: [], domains: [] };
    const ipFields = ['srcip', 'dstip', 'src', 'dst', 'ip', 'source_ip', 'dest_ip', 'client_ip', 'server_ip', 'source_address', 'destination_address'];
    
    for (const field of ipFields) {
      if (alertData[field] && this.isValidIP(alertData[field])) {
        iocs.ips.push(alertData[field]);
      }
    }
    
    if (typeof alertData === 'object') {
      this.searchForIPsInObject(alertData, iocs);
    }
    
    return iocs;
  }

  searchForIPsInObject(obj, iocs, depth = 0) {
    if (depth > 5) return;
    
    for (const key in obj) {
      if (typeof obj[key] === 'string') {
        const ipMatches = obj[key].match(/(?:\d{1,3}\.){3}\d{1,3}/g);
        if (ipMatches) {
          ipMatches.forEach(ip => {
            if (this.isValidIP(ip) && !iocs.ips.includes(ip)) {
              iocs.ips.push(ip);
            }
          });
        }
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        this.searchForIPsInObject(obj[key], iocs, depth + 1);
      }
    }
  }

  isValidIP(ip) {
    const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) return false;
    const octets = ip.split('.');
    return octets.every(octet => {
      const num = parseInt(octet, 10);
      return num >= 0 && num <= 255;
    });
  }

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
    
    // Check against known critical systems
    const isCriticalByName = this.knownThreats.critical_internal_systems.some(system => 
      system.hostname && hostname.toLowerCase().includes(system.hostname.toLowerCase()));
    
    const isCriticalByIP = this.knownThreats.critical_internal_systems.some(system => 
      system.ip === ip);
    
    // Common critical system indicators
    const criticalIndicators = ['dc', 'sql', 'database', 'fileserver', 'gateway', 'firewall', 'router'];
    const hasCriticalIndicator = criticalIndicators.some(indicator => 
      hostname.toLowerCase().includes(indicator));
    
    return isCriticalByName || isCriticalByIP || hasCriticalIndicator;
  }

  reloadBlacklist() {
    this.loadBlacklist();
    return { success: true, count: this.knownThreats.malicious_ips.length };
  }

  // New endpoint for internal threat analysis
  async analyzeInternalThreatsEndpoint(req, res) {
    try {
      const alert = req.body;
      const iocs = this.extractIOCs(alert);
      const enrichedIOCs = await this.enrichWithASN(iocs);
      const internalAnalysis = this.analyzeInternalThreats(alert, iocs, enrichedIOCs);
      
      res.json({
        status: 'success',
        analysis: internalAnalysis,
        ip_details: enrichedIOCs,
        metadata: {
          analyzedAt: new Date().toISOString(),
          total_ips: iocs.ips.length,
          internal_ips: iocs.ips.filter(ip => this.isInternalIP(ip)).length,
          agent: 'ThreatIntelAI'
        }
      });
    } catch (error) {
      res.status(500).json({
        status: 'error',
        error: error.message,
        timestamp: new Date().toISOString()
      });
    }
  }
}

const threatIntel = new ThreatIntelAI();

// Express routes
router.post('/analyze', (req, res) => {
  threatIntel.analyzeThreat(req, res);
});

// New endpoint for internal threat analysis
router.post('/analyze/internal', (req, res) => {
  threatIntel.analyzeInternalThreatsEndpoint(req, res);
});

router.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    agent: 'ThreatIntelAI',
    threat_counts: {
      malicious_ips: threatIntel.knownThreats.malicious_ips.length,
      malicious_domains: threatIntel.knownThreats.malicious_domains.length,
      internal_patterns: threatIntel.knownThreats.suspicious_internal_patterns.length,
      critical_systems: threatIntel.knownThreats.critical_internal_systems.length
    },
    asn_databases: {
      ipv4: threatIntel.asnDatabaseV4.size,
      ipv6: threatIntel.asnDatabaseV6.size
    },
    country_database: {
      loaded: threatIntel.countryReader !== null,
      type: 'MMDB',
      accuracy: 'High'
    },
    blacklist_loaded: threatIntel.knownThreats.malicious_ips.length > 0,
    asn_enrichment: true,
    country_enrichment: true,
    internal_threat_detection: true,
    capabilities: [
      'ip_reputation_checking',
      'geolocation_enrichment',
      'asn_enrichment',
      'internal_ip_detection',
      'critical_system_identification',
      'internal_threat_pattern_detection'
    ]
  });
});

router.get('/asn/lookup/:ip', (req, res) => {
  const asnInfo = threatIntel.findASNForIP(req.params.ip);
  if (asnInfo) {
    res.json({ ip: req.params.ip, ...asnInfo });
  } else {
    res.status(404).json({ error: 'ASN data not found for IP', ip: req.params.ip });
  }
});

router.get('/country/lookup/:ip', (req, res) => {
  const countryInfo = threatIntel.getCountryForIP(req.params.ip);
  res.json({
    ip: req.params.ip,
    ...countryInfo,
    timestamp: new Date().toISOString()
  });
});

router.get('/internal/check/:ip', (req, res) => {
  const ip = req.params.ip;
  const isInternal = threatIntel.isInternalIP(ip);
  const isCritical = threatIntel.isCriticalSystem(ip, '');
  const countryInfo = threatIntel.getCountryForIP(ip);
  
  res.json({
    ip,
    is_internal: isInternal,
    is_critical_system: isCritical,
    country: countryInfo.country,
    country_code: countryInfo.country_code,
    network_type: countryInfo.network_type || 'unknown',
    recommendations: isCritical ? [
      'Monitor access to this critical system',
      'Review authentication logs',
      'Ensure proper segmentation'
    ] : []
  });
});

router.get('/asn/stats', (req, res) => {
  res.json({
    ipv4_records: threatIntel.asnDatabaseV4.size,
    ipv6_records: threatIntel.asnDatabaseV6.size,
    top_organizations: Array.from(threatIntel.asnDatabaseV4.values())
      .slice(0, 10)
      .map(entry => entry.organization)
  });
});

router.post('/reload-blacklist', (req, res) => {
  const result = threatIntel.reloadBlacklist();
  res.json({
    message: 'Blacklist reloaded',
    ip_count: result.count,
    timestamp: new Date().toISOString()
  });
});

router.get('/blacklist', (req, res) => {
  res.json({
    ips: threatIntel.knownThreats.malicious_ips,
    count: threatIntel.knownThreats.malicious_ips.length,
    loaded_from: 'file'
  });
});

router.get('/internal/patterns', (req, res) => {
  res.json({
    suspicious_patterns: threatIntel.knownThreats.suspicious_internal_patterns,
    critical_systems: threatIntel.knownThreats.critical_internal_systems,
    count: {
      patterns: threatIntel.knownThreats.suspicious_internal_patterns.length,
      systems: threatIntel.knownThreats.critical_internal_systems.length
    }
  });
});

// Test endpoint for internal threat detection
router.post('/test/internal-threat', (req, res) => {
  const testAlert = {
    'Event Type': 'Internal Threat Test',
    'srcip': '192.168.1.100',
    'dstip': '192.168.1.1',
    'dstport': 445,
    'sentbyte': 15000000
  };
  
  const iocs = threatIntel.extractIOCs(testAlert);
  const internalAnalysis = threatIntel.analyzeInternalThreats(testAlert, iocs, {});
  
  res.json({
    test: 'Internal Threat Detection Test',
    alert: testAlert,
    analysis: internalAnalysis,
    verdict: internalAnalysis.has_internal_threats ? 'INTERNAL THREATS DETECTED' : 'No internal threats'
  });
});

module.exports = router;
module.exports.ThreatIntelAI = ThreatIntelAI;