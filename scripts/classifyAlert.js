module.exports = (alert) => {
  let type = 'unknown';
  let severity = 3; // Default: notice
  
  // Extract raw log if nested
  const log = alert.original || alert;

  // 1. Determine log type
  if (log.type === "traffic" || log.logid?.startsWith("0001")) {
    type = 'network';
  } 
  else if (log.subtype === "vpn" || log.logid?.startsWith("010103")) {
    type = 'app';
  } 
  else if (log.subtype === "wireless" || log.logid?.startsWith("010404")) {
    type = 'endpoint';
  }
  else if (log.logdesc?.includes("DHCP") || log.dhcp_msg) {
    type = 'network';
  }

  // 2. Calculate severity
  if (log.level === "error") severity = 5;
  else if (log.level === "alert") severity = 4;
  else if (log.action === "client-rst") severity = 4; // Special cases
  else if (log.logdesc?.includes("rogue")) severity = 5;

  // 3. Enrich with common fields
  return {
    original: log,
    type,
    severity,
    timestamp: log.eventtime || log.date + ' ' + log.time,
    device: log.devname || 'unknown',
    // Add threat intel placeholder
    threat_intel: null 
  };
};