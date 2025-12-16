const express = require('express');
const router = express.Router();
const axios = require('axios');

class EnhancedAppAI {
  constructor() {
    this.ollamaAvailable = true;
    this.model = 'phi3:mini';
    
    // Expanded threat intelligence databases
    this.wirelessThreats = {
      suspicious_manufacturers: [
        'TP-Link', 'D-Link', 'Tenda', 'Generic', 'Unknown', 
        'China Mobile', 'Xiaomi', 'Huawei', 'ZTE', 'Netgear',
        'Belkin', 'Linksys', 'ASUS', 'Buffalo'
      ],
      high_risk_manufacturers: [
        'Cisco', 'Ubiquiti', 'Aruba', 'Ruckus', 'MikroTik',
        'Meraki', 'Fortinet', 'Extreme Networks', 'Juniper'
      ],
      suspicious_ssid_patterns: [
        'Free', 'Guest', 'Public', 'Open', 'WiFi', 'Airport',
        'Hotel', 'Cafe', 'Starbucks', 'McDonald', 'AndroidAP',
        'iPhone', 'Mobile', 'Secure', 'Admin', 'Setup',
        'Test', 'Guest-WiFi', 'Visitor', 'Corporate', 'Employee'
      ],
      weak_encryption_types: ['Open', 'WEP', 'WPA', 'WPA-Personal'],
      strong_encryption_types: ['WPA2-Enterprise', 'WPA3', 'WPA2-AES']
    };
    
    // Expanded OUI database with risk levels
    this.ouiDatabase = {
      '7A:45:58': { name: 'Ubiquiti Networks', risk: 'high' },
      '78:AF:08': { name: 'GSEU', risk: 'medium' },
      'C0:D7:AA': { name: 'Aruba Networks', risk: 'high' },
      '00:0C:29': { name: 'VMware', risk: 'medium' },
      '00:50:56': { name: 'VMware', risk: 'medium' },
      '00:1A:A0': { name: 'Dell', risk: 'low' },
      '00:1E:68': { name: 'Intel', risk: 'low' },
      '00:25:9C': { name: 'Apple', risk: 'low' },
      '00:26:BB': { name: 'Apple', risk: 'low' },
      '00:23:12': { name: 'Cisco', risk: 'high' },
      '00:1B:2F': { name: 'Cisco', risk: 'high' },
      '00:1D:45': { name: 'Hewlett Packard', risk: 'medium' },
      '00:1E:4F': { name: 'Hewlett Packard', risk: 'medium' },
      '08:00:27': { name: 'VirtualBox', risk: 'medium' }
    };

    // Performance thresholds with severity levels
    this.performanceThresholds = {
      cpu_utilization: {
        critical: 95,
        high: 85,
        medium: 75,
        low: 50
      },
      memory_utilization: {
        critical: 95,
        high: 85,
        medium: 75,
        low: 50
      },
      interface_utilization: {
        critical: 90,
        high: 75,
        medium: 50,
        low: 25
      },
      zero_traffic_duration: 300 // 5 minutes
    };
  }

  // Enhanced address extraction for non-IP alerts
  extractAddresses(log) {
    console.log('🔍 ENHANCED APPAI - Extracting addresses from non-IP log');
    
    let source_address = 'Unknown';
    let destination_address = 'Unknown';
    let source_is_mac = false;
    let destination_is_mac = false;
    let source_is_hostname = false;
    let address_type = 'unknown';
    
    // Extract MAC addresses (priority for wireless events)
    if (log.bssid && log.bssid !== 'N/A' && log.bssid !== 'Unknown') {
      source_address = log.bssid.toUpperCase();
      source_is_mac = true;
      address_type = 'bssid';
      console.log(`📶 Found BSSID (AP MAC): ${source_address}`);
    }
    
    if (log.stamac && log.stamac !== 'N/A' && log.stamac !== 'Unknown') {
      destination_address = log.stamac.toUpperCase();
      destination_is_mac = true;
      address_type = 'mac';
      console.log(`📶 Found station MAC: ${destination_address}`);
    }
    
    if (log.mac && log.mac !== 'N/A' && log.mac !== 'Unknown') {
      const cleanMAC = log.mac.toUpperCase();
      if (source_address === 'Unknown') {
        source_address = cleanMAC;
        source_is_mac = true;
        address_type = 'mac';
      } else if (destination_address === 'Unknown') {
        destination_address = cleanMAC;
        destination_is_mac = true;
      }
      console.log(`📶 Found device MAC: ${cleanMAC}`);
    }
    
    // Extract hostnames (non-IP identifier)
    if (log.hostname && log.hostname !== 'N/A' && log.hostname !== 'Unknown') {
      if (source_address === 'Unknown') {
        source_address = log.hostname;
        source_is_hostname = true;
        address_type = 'hostname';
        console.log(`🏷️ Found hostname: ${source_address}`);
      }
    }
    
    if (log.devname && log.devname !== 'N/A' && log.devname !== 'Unknown') {
      if (destination_address === 'Unknown') {
        destination_address = log.devname;
        address_type = 'device_name';
        console.log(`🖥️ Found device name: ${destination_address}`);
      }
    }
    
    // Fallback: Extract any string that looks like an identifier
    if (source_address === 'Unknown') {
      for (const [key, value] of Object.entries(log)) {
        if (typeof value === 'string' && value.length > 0 && value !== 'N/A' && value !== 'Unknown') {
          // Check if it's an identifier (not IP, not too long)
          if (value.length <= 50 && !this.isValidIP(value)) {
            source_address = value;
            console.log(`🔤 Using ${key} as source identifier: ${value}`);
            break;
          }
        }
      }
    }
    
    return {
      source_address,
      source_is_mac,
      source_is_hostname,
      destination_address,
      destination_is_mac,
      address_type,
      has_ip_address: false,
      has_mac_address: source_is_mac || destination_is_mac,
      is_non_ip_alert: true
    };
  }

  // Detect suspicious MAC patterns
  detectSuspiciousMAC(mac) {
    if (!mac || mac === 'Unknown' || mac === 'N/A') return null;
    
    const cleanMAC = mac.toUpperCase().replace(/[.:-]/g, '');
    
    // Check for multicast/broadcast
    if (cleanMAC.startsWith('01005E') || cleanMAC.startsWith('3333') || 
        cleanMAC === 'FFFFFFFFFFFF') {
      return { type: 'multicast_broadcast', risk: 'high' };
    }
    
    // Check for VMware/VirtualBox MACs (could indicate VMs)
    if (cleanMAC.startsWith('000C29') || cleanMAC.startsWith('080027')) {
      return { type: 'virtual_machine', risk: 'medium' };
    }
    
    // Check for locally administered MAC (2nd LSB of first byte is 1)
    const firstByte = parseInt(cleanMAC.substring(0, 2), 16);
    if ((firstByte & 0x02) !== 0) {
      return { type: 'locally_administered', risk: 'medium' };
    }
    
    return null;
  }

  // Analyze wireless threats with enhanced detection
  assessWirelessRisk(alert) {
    const ssid = alert.ssid || 'Unknown';
    const bssid = alert.bssid || 'Unknown';
    const security = alert.security || 'Unknown';
    const encryption = alert.encryption || 'Unknown';
    const manufacturer = alert.manuf || this.getManufacturerFromMAC(bssid);
    const signal = parseInt(alert.signal || -100);
    const noise = parseInt(alert.noise || -100);
    const snr = Math.abs(signal - noise);
    const channel = parseInt(alert.channel || 0);
    
    let threat_level = 'low';
    let attack_type = 'wireless_monitoring';
    let confidence = 0.5;
    let key_findings = [];
    let immediate_actions = ['Monitor wireless environment'];
    let investigation_steps = ['Review wireless security logs'];
    let business_impact = 'low';
    
    // CRITICAL: Rogue AP detection
    if (alert.logdesc?.includes('Rogue AP') || alert.action?.includes('rogue') || 
        alert['Event Type']?.includes('rogue')) {
      threat_level = 'critical';
      attack_type = 'rogue_access_point';
      confidence = 0.9;
      business_impact = 'high';
      key_findings.push('🚨 ROGUE ACCESS POINT DETECTED');
      immediate_actions = [
        'IMMEDIATE: Isolate affected network segment',
        'Locate and disable rogue AP',
        'Notify security team'
      ];
      investigation_steps = [
        'Identify physical location of AP',
        'Check for unauthorized devices',
        'Review access control lists'
      ];
    }
    
    // HIGH: Weak encryption
    if (this.wirelessThreats.weak_encryption_types.includes(security) || 
        encryption === 'None' || encryption === 'Open') {
      threat_level = Math.max(this.threatLevelToNumber(threat_level), this.threatLevelToNumber('high'));
      attack_type = 'weak_encryption';
      confidence = Math.max(confidence, 0.8);
      key_findings.push(`Weak/No encryption: ${security}/${encryption}`);
      immediate_actions.push('Upgrade to WPA2/WPA3 encryption');
    }
    
    // HIGH: Suspicious SSID patterns
    if (this.containsSuspiciousPattern(ssid, this.wirelessThreats.suspicious_ssid_patterns)) {
      threat_level = Math.max(this.threatLevelToNumber(threat_level), this.threatLevelToNumber('high'));
      confidence = Math.max(confidence, 0.7);
      key_findings.push(`Suspicious SSID pattern: "${ssid}"`);
      investigation_steps.push('Investigate SSID impersonation');
    }
    
    // MEDIUM: High-risk manufacturer
    const manufInfo = this.getManufacturerInfo(manufacturer);
    if (manufInfo && manufInfo.risk === 'high') {
      threat_level = Math.max(this.threatLevelToNumber(threat_level), this.threatLevelToNumber('medium'));
      key_findings.push(`High-risk manufacturer: ${manufacturer} (commonly targeted)`);
    }
    
    // MEDIUM: Strong signal (-60dBm or better)
    if (signal > -60) {
      key_findings.push(`Strong signal detected: ${signal}dBm (close proximity)`);
      if (threat_level === 'critical' || threat_level === 'high') {
        immediate_actions.push('Locate physical device');
      }
    }
    
    // LOW: Poor SNR
    if (snr < 20) {
      key_findings.push(`Poor signal quality (SNR: ${snr}dB)`);
      investigation_steps.push('Check for interference or jamming');
    }
    
    // Check MAC address anomalies
    const macAnalysis = this.detectSuspiciousMAC(bssid);
    if (macAnalysis) {
      key_findings.push(`MAC anomaly: ${macAnalysis.type} (${macAnalysis.risk} risk)`);
      if (macAnalysis.risk === 'high') {
        threat_level = Math.max(this.threatLevelToNumber(threat_level), this.threatLevelToNumber('high'));
      }
    }
    
    return {
      threat_level: this.numberToThreatLevel(this.threatLevelToNumber(threat_level)),
      attack_type,
      confidence,
      key_findings,
      immediate_actions,
      investigation_steps,
      business_impact,
      wireless_analysis: {
        ssid,
        bssid,
        manufacturer,
        manufacturer_risk: manufInfo?.risk || 'unknown',
        security,
        encryption,
        signal_strength: signal,
        noise_level: noise,
        snr,
        channel,
        is_rogue: alert.logdesc?.includes('Rogue') || false,
        on_wire: alert.onwire === 'yes'
      }
    };
  }

  // Analyze performance events with internal threat detection
  assessPerformanceRisk(alert) {
    const eventType = alert['Event Type'] || '';
    const intfUtil = parseFloat(alert.inIntfUtil || alert.outIntfUtil || 0);
    const recvBits = parseFloat(alert.recvBitsPerSec || 0);
    const sentBits = parseFloat(alert.sentBitsPerSec || 0);
    const intfName = alert.intfName || 'Unknown';
    const hostName = alert.hostName || alert.devname || 'Unknown';
    
    let threat_level = 'low';
    let attack_type = 'performance_monitoring';
    let confidence = 0.7;
    let key_findings = ['System performance monitoring event'];
    let immediate_actions = ['Review performance metrics'];
    let investigation_steps = ['Check historical trends'];
    let business_impact = 'low';
    
    // CRITICAL: Critical interface down (zero traffic on expected link)
    if (recvBits === 0 && sentBits === 0 && intfUtil === 0) {
      // Check if this is a critical interface
      const isCritical = this.isCriticalInterface(intfName, hostName);
      if (isCritical) {
        threat_level = 'critical';
        attack_type = 'critical_interface_down';
        confidence = 0.9;
        business_impact = 'high';
        key_findings.push(`🚨 CRITICAL INTERFACE DOWN: ${intfName} on ${hostName}`);
        immediate_actions = [
          'IMMEDIATE: Check physical connectivity',
          'Verify interface status',
          'Check for DoS attack'
        ];
        investigation_steps = [
          'Review link status changes',
          'Check for hardware failures',
          'Monitor for service impact'
        ];
      } else {
        threat_level = 'medium';
        attack_type = 'interface_down_or_idle';
        key_findings.push(`Interface ${intfName} shows no traffic`);
      }
    }
    
    // HIGH: High interface utilization (potential internal DoS)
    if (intfUtil >= this.performanceThresholds.interface_utilization.critical) {
      threat_level = 'high';
      attack_type = 'interface_saturation';
      confidence = 0.8;
      business_impact = 'medium';
      key_findings.push(`HIGH interface utilization: ${intfUtil}%`);
      immediate_actions.push('Investigate traffic sources');
      investigation_steps.push('Identify bandwidth-consuming applications');
    }
    
    // MEDIUM: Unusual traffic patterns
    if ((recvBits > 0 && sentBits === 0) || (recvBits === 0 && sentBits > 0)) {
      // Asymmetric traffic could indicate scanning or exfiltration
      threat_level = Math.max(this.threatLevelToNumber(threat_level), this.threatLevelToNumber('medium'));
      attack_type = 'asymmetric_traffic';
      key_findings.push(`Asymmetric traffic pattern detected`);
      investigation_steps.push('Check for internal scanning or data exfiltration');
    }
    
    return {
      threat_level,
      attack_type,
      confidence,
      key_findings,
      immediate_actions,
      investigation_steps,
      business_impact,
      performance_analysis: {
        interface: intfName,
        alias: alert.intfAlias || 'N/A',
        receive_bps: recvBits,
        send_bps: sentBits,
        utilization: intfUtil,
        is_critical: this.isCriticalInterface(intfName, hostName),
        host_name: hostName
      }
    };
  }

  // Analyze SNMP events
  assessSNMPRisk(alert) {
    const rawLog = alert['Raw Event Log'] || '';
    
    let threat_level = 'low';
    let attack_type = 'snmp_management';
    let confidence = 0.6;
    let key_findings = ['SNMP management event'];
    let immediate_actions = ['Verify device health'];
    let investigation_steps = ['Check SNMP configuration'];
    let business_impact = 'low';
    
    // HIGH: Cold/Warm Start (potential unauthorized reboot)
    if (rawLog.includes('Cold Start Trap') || rawLog.includes('warmStart')) {
      threat_level = 'high';
      attack_type = 'unauthorized_reboot';
      confidence = 0.7;
      business_impact = 'medium';
      key_findings.push('Device reboot detected via SNMP');
      immediate_actions = [
        'Verify authorized maintenance window',
        'Check power/UPS status'
      ];
      investigation_steps = [
        'Review reboot reason',
        'Check for physical access',
        'Monitor for further reboots'
      ];
    }
    
    // MEDIUM: Authentication failure or suspicious community
    if (rawLog.includes('authenticationFailure') || 
        (rawLog.includes('community') && rawLog.includes('public'))) {
      threat_level = 'medium';
      attack_type = 'snmp_security_violation';
      key_findings.push('Weak SNMP authentication detected');
      immediate_actions.push('Change SNMP community strings');
      investigation_steps.push('Review SNMP access controls');
    }
    
    // Extract device info
    const deviceInfo = this.extractDeviceInfo(rawLog);
    if (deviceInfo) {
      key_findings.push(`Device: ${deviceInfo.type || 'Unknown'} - ${deviceInfo.band || ''}`);
    }
    
    return {
      threat_level,
      attack_type,
      confidence,
      key_findings,
      immediate_actions,
      investigation_steps,
      business_impact,
      snmp_analysis: {
        trap_type: this.extractTrapType(rawLog),
        uptime: rawLog.includes('Uptime:') ? rawLog.match(/Uptime: ([^\n]+)/)?.[1] : 'Unknown',
        community: this.extractCommunity(rawLog),
        device_info: deviceInfo
      }
    };
  }

  // Analyze DHCP events for internal threats
  assessDHCPRisk(alert) {
    const mac = alert.mac || 'Unknown';
    const ip = alert.ip || 'Unknown';
    const hostname = alert.hostname || 'Unknown';
    const interfaceName = alert.interface || 'Unknown';
    const dhcpMsg = alert.dhcp_msg || 'Unknown';
    
    let threat_level = 'low';
    let attack_type = 'dhcp_assignment';
    let confidence = 0.6;
    let key_findings = [`DHCP ${dhcpMsg} for ${mac}`];
    let immediate_actions = ['Monitor DHCP lease'];
    let investigation_steps = ['Review DHCP scope utilization'];
    let business_impact = 'low';
    
    // HIGH: Suspicious MAC patterns
    const macAnalysis = this.detectSuspiciousMAC(mac);
    if (macAnalysis) {
      threat_level = macAnalysis.risk === 'high' ? 'high' : 'medium';
      attack_type = 'suspicious_mac_assignment';
      key_findings.push(`Suspicious MAC address: ${macAnalysis.type}`);
      immediate_actions.push('Investigate device authorization');
      investigation_steps.push('Check MAC filtering rules');
    }
    
    // MEDIUM: Personal/unknown device on corporate network
    const suspiciousHostnames = [
      'Android', 'iPhone', 'iPad', 'Windows', 'DESKTOP-', 'LAPTOP-',
      'User-', 'Test', 'Unknown', 'Guest', 'Mobile', 'Phone'
    ];
    
    if (suspiciousHostnames.some(pattern => 
        hostname.toLowerCase().includes(pattern.toLowerCase()))) {
      threat_level = Math.max(this.threatLevelToNumber(threat_level), this.threatLevelToNumber('medium'));
      attack_type = 'personal_device_on_corp_network';
      key_findings.push(`Personal/unknown device: ${hostname}`);
      immediate_actions.push('Verify BYOD policy compliance');
    }
    
    // MEDIUM: Short lease time (potential DHCP exhaustion)
    const leaseTime = parseInt(alert.lease || 0);
    if (leaseTime > 0 && leaseTime < 300) { // Less than 5 minutes
      threat_level = Math.max(this.threatLevelToNumber(threat_level), this.threatLevelToNumber('medium'));
      attack_type = 'short_dhcp_lease';
      key_findings.push(`Short DHCP lease: ${leaseTime} seconds`);
      investigation_steps.push('Check for DHCP exhaustion attacks');
    }
    
    // Check if IP is in suspicious range
    if (ip !== 'Unknown' && this.isSuspiciousIPRange(ip)) {
      key_findings.push(`Assigned to suspicious IP range: ${ip}`);
      investigation_steps.push('Verify IP address assignment');
    }
    
    return {
      threat_level: this.numberToThreatLevel(this.threatLevelToNumber(threat_level)),
      attack_type,
      confidence,
      key_findings,
      immediate_actions,
      investigation_steps,
      business_impact,
      dhcp_analysis: {
        mac_address: mac,
        assigned_ip: ip,
        hostname,
        interfaceName,
        lease_time: leaseTime,
        dhcp_message: dhcpMsg,
        mac_analysis: macAnalysis
      }
    };
  }

  // Enhanced internal threat detection for VPN events
  assessVPNRisk(alert) {
    const action = alert.action || 'Unknown';
    const status = alert.status || 'Unknown';
    const reason = alert.reason || 'Not provided';
    const desc = alert.desc || 'Not provided';
    const user = alert.user || 'N/A';
    const remip = alert.remip || 'Unknown';
    const srccountry = alert.srccountry || 'Unknown';
    const tunneltype = alert.tunneltype || 'Unknown';
    
    let threat_level = 'low';
    let attack_type = 'vpn_event';
    let confidence = 0.5;
    let key_findings = [`VPN ${action} event`];
    let immediate_actions = ['Review VPN logs'];
    let investigation_steps = ['Check VPN configuration'];
    let business_impact = 'low';
    
    // CRITICAL: VPN authentication bypass or critical failure
    if (status === 'failed' && reason?.includes('authentication')) {
      threat_level = 'critical';
      attack_type = 'vpn_authentication_bypass_attempt';
      confidence = 0.9;
      business_impact = 'high';
      key_findings.push('🚨 VPN AUTHENTICATION FAILURE - Possible credential attack');
      immediate_actions = [
        'IMMEDIATE: Review authentication logs',
        'Check for brute force attempts',
        'Notify security team'
      ];
      investigation_steps = [
        'Review failed login patterns',
        'Check user account status',
        'Monitor for further attempts'
      ];
    }
    
    // HIGH: IPsec configuration mismatch (potential attack)
    if (reason?.includes('peer SA proposal not match')) {
      threat_level = 'high';
      attack_type = 'ipsec_configuration_attack';
      confidence = 0.8;
      key_findings.push('IPsec configuration mismatch - Possible attack probing');
      immediate_actions.push('Review IPsec policies and proposals');
      investigation_steps.push('Check for VPN gateway spoofing');
    }
    
    // HIGH: SSL VPN alert with security implications
    if (action === 'ssl-alert' && desc?.includes('handshake') || desc?.includes('certificate')) {
      threat_level = 'high';
      attack_type = 'ssl_vpn_security_alert';
      key_findings.push(`SSL VPN security alert: ${desc}`);
      immediate_actions.push('Verify SSL certificates');
      investigation_steps.push('Check for man-in-the-middle attacks');
    }
    
    // MEDIUM: VPN connection from high-risk country
    const highRiskCountries = ['RU', 'CN', 'IR', 'KP', 'SY', 'VE', 'NG'];
    if (highRiskCountries.includes(srccountry)) {
      threat_level = Math.max(this.threatLevelToNumber(threat_level), this.threatLevelToNumber('medium'));
      attack_type = 'vpn_from_high_risk_country';
      key_findings.push(`VPN connection from high-risk country: ${srccountry}`);
      investigation_steps.push('Review geo-blocking policies');
    }
    
    // MEDIUM: Unusual user or service account
    if (user !== 'N/A' && (user.includes('svc_') || user.includes('admin') || user === 'root')) {
      key_findings.push(`Service/Admin account used: ${user}`);
      investigation_steps.push('Verify service account usage');
    }
    
    return {
      threat_level,
      attack_type,
      confidence,
      key_findings,
      immediate_actions,
      investigation_steps,
      business_impact,
      vpn_analysis: {
        remote_ip: remip,
        country: srccountry,
        user,
        tunnel_type: tunneltype,
        status,
        reason,
        description: desc,
        is_high_risk_country: highRiskCountries.includes(srccountry)
      }
    };
  }

  // Helper methods
  getManufacturerFromMAC(mac) {
    if (!mac || mac === 'Unknown' || mac === 'N/A') return 'Unknown';
    
    const cleanMAC = mac.replace(/[.:-]/g, '').toUpperCase();
    const oui = cleanMAC.substring(0, 6);
    
    for (const [ouiPrefix, info] of Object.entries(this.ouiDatabase)) {
      const cleanOUI = ouiPrefix.replace(/:/g, '').toUpperCase();
      if (oui.startsWith(cleanOUI)) {
        return info.name;
      }
    }
    
    return 'Unknown Manufacturer';
  }

  getManufacturerInfo(manufacturer) {
    if (!manufacturer || manufacturer === 'Unknown') return null;
    
    // Check high-risk manufacturers
    if (this.wirelessThreats.high_risk_manufacturers.some(m => 
        manufacturer.toLowerCase().includes(m.toLowerCase()))) {
      return { name: manufacturer, risk: 'high' };
    }
    
    // Check suspicious manufacturers
    if (this.wirelessThreats.suspicious_manufacturers.some(m => 
        manufacturer.toLowerCase().includes(m.toLowerCase()))) {
      return { name: manufacturer, risk: 'medium' };
    }
    
    return { name: manufacturer, risk: 'low' };
  }

  containsSuspiciousPattern(text, patterns) {
    if (!text || text === 'Unknown') return false;
    const lowerText = text.toLowerCase();
    return patterns.some(pattern => lowerText.includes(pattern.toLowerCase()));
  }

  isCriticalInterface(interfaceName, hostName) {
    const criticalInterfaces = [
      'port1', 'port0', 'wan1', 'wan2', 'uplink', 'trunk',
      'vlan1', 'mgmt', 'management'
    ];
    
    const criticalHosts = [
      'firewall', 'router', 'switch', 'gateway', 'fw-', 'rt-'
    ];
    
    const isCriticalInterface = criticalInterfaces.some(ci => 
        interfaceName.toLowerCase().includes(ci));
    
    const isCriticalHost = criticalHosts.some(ch => 
        hostName.toLowerCase().includes(ch));
    
    return isCriticalInterface || isCriticalHost;
  }

  extractDeviceInfo(rawLog) {
    if (!rawLog) return null;
    
    // Extract from Aruba format
    const bandMatch = rawLog.match(/\"2\.4GHz\"|\"5GHz\"/);
    const macMatch = rawLog.match(/Hex-STRING: ([0-9A-F ]+)/);
    
    return {
      type: rawLog.includes('Aruba') ? 'Aruba Access Point' : 'Network Device',
      band: bandMatch ? bandMatch[0].replace(/"/g, '') : null,
      mac: macMatch ? macMatch[1] : null
    };
  }

  extractTrapType(rawLog) {
    if (!rawLog) return 'Unknown';
    if (rawLog.includes('Cold Start')) return 'coldStart';
    if (rawLog.includes('warmStart')) return 'warmStart';
    if (rawLog.includes('linkDown')) return 'linkDown';
    if (rawLog.includes('linkUp')) return 'linkUp'; 
    return 'other';
  }

  extractCommunity(rawLog) {
    if (!rawLog) return 'public';
    const match = rawLog.match(/community (\S+)/);
    return match ? match[1] : 'public';
  }

  isSuspiciousIPRange(ip) {
    if (!ip || ip === 'Unknown') return false;
    
    // Suspicious internal ranges that shouldn't have DHCP
    const suspiciousRanges = [
      '169.254.', // APIPA
      '0.0.0.0',
      '255.255.255.255',
      '127.0.0.1'
    ];
    
    return suspiciousRanges.some(range => ip.startsWith(range));
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

  threatLevelToNumber(level) {
    const levels = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 };
    return levels[level] || 1;
  }

  numberToThreatLevel(num) {
    const levels = { 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' };
    return levels[num] || 'low';
  }

  // Main analysis method
  async analyze(alert) {
    console.log('🔍 ENHANCED APPAI - Analyzing alert:', alert['Event Type'] || 'Unknown');
    
    // Determine alert type
    const eventType = alert['Event Type'] || '';
    const subtype = alert.subtype || '';
    const logdesc = alert.logdesc || '';
    
    let analysis;
    
    // Route to appropriate analyzer
    if (subtype === 'wireless' || logdesc.includes('Rogue AP') || logdesc.includes('wireless')) {
      analysis = this.assessWirelessRisk(alert);
    } else if (eventType.includes('PH_DEV_MON') || eventType.includes('MON_')) {
      analysis = this.assessPerformanceRisk(alert);
    } else if (eventType.includes('Aruba') || alert['Raw Event Log']?.includes('SNMP') || 
               logdesc.includes('SNMP') || alert['Raw Event Log']?.includes('TRAP')) {
      analysis = this.assessSNMPRisk(alert);
    } else if (logdesc.includes('DHCP') || (subtype === 'system' && alert.dhcp_msg)) {
      analysis = this.assessDHCPRisk(alert);
    } else if (subtype === 'vpn' || logdesc.includes('VPN') || logdesc.includes('IPsec')) {
      analysis = this.assessVPNRisk(alert);
    } else {
      // Default generic analysis
      analysis = {
        threat_level: 'low',
        attack_type: 'unknown_event',
        confidence: 0.3,
        key_findings: ['Unknown event type - Manual review recommended'],
        immediate_actions: ['Review event logs manually'],
        investigation_steps: ['Check with security team'],
        business_impact: 'low',
        _analyzed_by: 'app_generic_engine'
      };
    }
    
    // Add metadata
    analysis._analyzed_by = 'EnhancedAppAI';
    analysis._analysis_method = 'rule_based';
    analysis._timestamp = new Date().toISOString();
    
    return analysis;
  }
}

// Create and export instance
const enhancedAppAI = new EnhancedAppAI();

// Express routes
router.post('/analyze', async (req, res) => {
  const requestId = Math.random().toString(36).substring(2, 10);
  console.log(`[${requestId}] 📡 ENHANCED APPAI - Processing request`);
  
  try {
    const alert = req.body;
    const addresses = enhancedAppAI.extractAddresses(alert);
    const analysis = await enhancedAppAI.analyze(alert);
    
    const response = {
      status: 'success',
      analysis,
      addresses: {
        source: addresses.source_address,
        source_type: addresses.source_is_mac ? 'mac' : 
                    addresses.source_is_hostname ? 'hostname' : 'unknown',
        destination: addresses.destination_address,
        destination_type: addresses.destination_is_mac ? 'mac' : 'unknown',
        address_type: addresses.address_type,
        has_ip: addresses.has_ip_address,
        has_mac: addresses.has_mac_address,
        is_non_ip_alert: addresses.is_non_ip_alert
      },
      metadata: {
        analyzedAt: new Date().toISOString(),
        agent: 'EnhancedAppAI',
        processingTime: '0.1s',
        request_id: requestId,
        alert_type: alert['Event Type'] || 'Unknown',
        capabilities: [
          'non_ip_threat_detection',
          'wireless_security',
          'performance_monitoring',
          'dhcp_security',
          'snmp_security',
          'vpn_security'
        ]
      }
    };
    
    console.log(`[${requestId}] ✅ ENHANCED APPAI - Analysis complete: ${analysis.threat_level}`);
    res.json(response);
    
  } catch (error) {
    console.error(`[${requestId}] ❌ ENHANCED APPAI - Error:`, error.message);
    res.status(500).json({
      status: 'error',
      error: error.message,
      request_id: requestId,
      agent: 'EnhancedAppAI'
    });
  }
});

router.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    agent: 'EnhancedAppAI',
    version: '3.0',
    capabilities: [
      'non_ip_alert_analysis',
      'wireless_threat_detection',
      'performance_anomaly_detection',
      'dhcp_security_analysis',
      'snmp_trap_analysis',
      'vpn_security_monitoring',
      'mac_address_analysis',
      'internal_threat_detection'
    ],
    threat_intelligence: {
      wireless_threats: enhancedAppAI.wirelessThreats,
      performance_thresholds: enhancedAppAI.performanceThresholds,
      oui_database_size: Object.keys(enhancedAppAI.ouiDatabase).length
    },
    timestamp: new Date().toISOString()
  });
});

module.exports = router;
module.exports.EnhancedAppAI = EnhancedAppAI;