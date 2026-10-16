const IpGeolocator = require('../security/ip_geolocator');

/**
 * SMTP Received Headers & Network Route Analyzer
 * Extracts full hop trail, intermediate relays, delays and origin IP.
 */
class HeaderAnalyzer {
  /**
   * Analyze all Received headers to reconstruct the network path
   * @param {Object} headers 
   * @returns {Object} Network route analysis
   */
  static analyzeNetworkRoute(headers) {
    const rawReceived = headers['received'] || [];
    const hops = [];

    // Note: Received headers are appended at top by each MTA.
    // So rawReceived[0] is the destination/last MTA.
    // rawReceived[length - 1] is the initial client/origin hop.
    // We reverse them to get chronological order (Hop 1 = origin, Hop N = destination).
    const chronological = [...rawReceived].reverse();

    for (let i = 0; i < chronological.length; i++) {
      const hopNumber = i + 1;
      const hopRaw = chronological[i];
      const parsedHop = this.parseReceivedHop(hopRaw, hopNumber);
      hops.push(parsedHop);
    }

    // Calculate latency/delay between consecutive hops
    for (let i = 0; i < hops.length; i++) {
      if (i > 0 && hops[i].timestamp && hops[i - 1].timestamp) {
        const diffMs = hops[i].timestamp.getTime() - hops[i - 1].timestamp.getTime();
        hops[i].delayMs = Math.max(0, diffMs);
        hops[i].delayFormatted = this.formatDelay(hops[i].delayMs);
      } else {
        hops[i].delayMs = 0;
        hops[i].delayFormatted = '0s (Salto inicial)';
      }
    }

    // Determine the true Originating Public IP
    // Search from first hop onwards for the first valid public IP
    let originIp = null;
    let originHostname = null;
    let originHopIndex = -1;

    for (let i = 0; i < hops.length; i++) {
      const hop = hops[i];
      if (hop.senderIp && !this.isPrivateOrReservedIp(hop.senderIp)) {
        originIp = hop.senderIp;
        originHostname = hop.senderHost;
        originHopIndex = i + 1;
        break;
      }
    }

    // Fallback: If no public IP found in senderIp, check IPs in hops
    if (!originIp) {
      for (let i = 0; i < hops.length; i++) {
        const hop = hops[i];
        for (const ip of hop.allIps) {
          if (!this.isPrivateOrReservedIp(ip)) {
            originIp = ip;
            originHostname = hop.senderHost;
            originHopIndex = i + 1;
            break;
          }
        }
        if (originIp) break;
      }
    }

    // If still none, check private IP or first hop
    if (!originIp && hops.length > 0) {
      originIp = hops[0].senderIp || (hops[0].allIps.length > 0 ? hops[0].allIps[0] : 'No identificada');
      originHostname = hops[0].senderHost || 'Local/Desconocido';
      originHopIndex = 1;
    }

    // Total transmission time
    let totalTransitMs = 0;
    if (hops.length >= 2 && hops[0].timestamp && hops[hops.length - 1].timestamp) {
      totalTransitMs = Math.max(0, hops[hops.length - 1].timestamp.getTime() - hops[0].timestamp.getTime());
    }

    return {
      totalHops: hops.length,
      originIp: originIp || 'No detectada',
      originHostname: originHostname || 'Desconocido',
      originHopIndex,
      isOriginPrivate: originIp ? this.isPrivateOrReservedIp(originIp) : false,
      originGeo: IpGeolocator.analyzeOffline(originIp),
      totalTransitFormatted: this.formatDelay(totalTransitMs),
      hops
    };
  }

  /**
   * Parse a single Received: header
   */
  static parseReceivedHop(raw, hopNumber) {
    const clean = raw.replace(/\r?\n\s*/g, ' ').trim();

    // Split date portion (everything after the last semicolon)
    const semiIdx = clean.lastIndexOf(';');
    let dateStr = null;
    let routeStr = clean;
    let timestamp = null;

    if (semiIdx > 0) {
      routeStr = clean.slice(0, semiIdx).trim();
      dateStr = clean.slice(semiIdx + 1).trim();
      const d = new Date(dateStr);
      if (!isNaN(d.getTime())) {
        timestamp = d;
      }
    }

    // Extract sender ("from ...")
    let senderHost = null;
    let senderIp = null;
    const fromMatch = routeStr.match(/\bfrom\s+([^\s(]+)(?:\s*\(([^)]*)\))?/i);
    if (fromMatch) {
      senderHost = fromMatch[1];
      const parenContent = fromMatch[2] || '';
      // Try to find IP inside parenthesis
      const ipInParen = parenContent.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/) ||
                        parenContent.match(/\[([0-9a-fA-F:.]+)\]/);
      if (ipInParen) {
        senderIp = ipInParen[1];
      }
    }

    // Extract receiver ("by ...")
    let receiverHost = null;
    const byMatch = routeStr.match(/\bby\s+([^\s(]+)/i);
    if (byMatch) {
      receiverHost = byMatch[1];
    }

    // Extract protocol/encryption ("with ...")
    let protocol = null;
    const withMatch = routeStr.match(/\bwith\s+([^\s;]+(?:\s+id|\s+for)?)/i);
    if (withMatch) {
      protocol = withMatch[1].replace(/\s+(id|for)$/i, '').trim();
    }

    // Extract all IPv4 and IPv6 present in the hop
    const allIps = [];
    const ipv4Matches = clean.matchAll(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g);
    for (const m of ipv4Matches) {
      if (this.isValidIPv4(m[1]) && !allIps.includes(m[1])) {
        allIps.push(m[1]);
      }
    }

    const ipv6Matches = clean.matchAll(/\[([0-9a-fA-F:]{3,39})\]/g);
    for (const m of ipv6Matches) {
      if (m[1].includes(':') && !allIps.includes(m[1])) {
        allIps.push(m[1]);
      }
    }

    // If senderIp was not found, pick first detected IP
    if (!senderIp && allIps.length > 0) {
      senderIp = allIps[0];
    }

    return {
      hopNumber,
      senderHost: senderHost || 'Desconocido',
      senderIp: senderIp || null,
      receiverHost: receiverHost || 'Desconocido',
      protocol: protocol || 'SMTP estándar',
      timestamp,
      dateFormatted: timestamp ? timestamp.toLocaleString('es-ES', { dateStyle: 'short', timeStyle: 'medium' }) : (dateStr || 'No especificada'),
      allIps,
      isSenderIpPrivate: senderIp ? this.isPrivateOrReservedIp(senderIp) : false,
      geo: senderIp ? IpGeolocator.analyzeOffline(senderIp) : null,
      raw: clean
    };
  }

  /**
   * Check if an IP is in private, loopback or link-local ranges
   */
  static isPrivateOrReservedIp(ip) {
    if (!ip) return false;
    // IPv4 private ranges
    if (ip.startsWith('10.') || ip.startsWith('127.') || ip.startsWith('192.168.') || ip === '0.0.0.0') return true;
    if (ip.startsWith('169.254.')) return true; // Link-local
    // 172.16.0.0 - 172.31.255.255
    if (ip.startsWith('172.')) {
      const parts = ip.split('.');
      if (parts.length >= 2) {
        const second = parseInt(parts[1], 10);
        if (second >= 16 && second <= 31) return true;
      }
    }
    // IPv6 private/loopback
    if (ip === '::1' || ip === '::' || ip.toLowerCase().startsWith('fe80:') || ip.toLowerCase().startsWith('fc00:')) return true;
    return false;
  }

  /**
   * Validate IPv4 octets
   */
  static isValidIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every(p => {
      const n = parseInt(p, 10);
      return !isNaN(n) && n >= 0 && n <= 255 && p === String(n);
    });
  }

  /**
   * Format milliseconds into human readable delay
   */
  static formatDelay(ms) {
    if (ms <= 0) return '0 seg';
    const seconds = Math.floor(ms / 1000);
    if (seconds < 60) return `+${seconds} seg`;
    const minutes = Math.floor(seconds / 60);
    const remSec = seconds % 60;
    if (minutes < 60) return `+${minutes} min ${remSec} seg`;
    const hours = Math.floor(minutes / 60);
    return `+${hours} h ${minutes % 60} min`;
  }
}

module.exports = HeaderAnalyzer;

