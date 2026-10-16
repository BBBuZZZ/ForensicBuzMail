/**
 * IP Geolocation Engine (Offline RIR / Subnet Database + Online API Lookup)
 * Part of ForensicBuzMail.
 */

// Offline IANA IPv4 Allocation Table to Regional Internet Registries (RIRs)
const RIR_MAP = {
  // RIPE NCC (Europe, Middle East, Central Asia)
  ripe: [2, 5, 24, 25, 31, 37, 46, 51, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 109, 141, 145, 147, 149, 151, 176, 178, 185, 188, 193, 194, 195, 212, 213, 217],
  // ARIN (USA, Canada, parts of Caribbean)
  arin: [3, 4, 6, 7, 8, 9, 11, 12, 13, 15, 16, 17, 18, 19, 20, 23, 26, 32, 34, 35, 38, 40, 44, 47, 50, 52, 54, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 96, 97, 98, 99, 100, 104, 107, 108, 128, 129, 130, 131, 132, 134, 135, 136, 137, 138, 139, 140, 142, 143, 144, 146, 148, 152, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 172, 173, 174, 184, 192, 198, 199, 204, 205, 206, 207, 208, 209, 216],
  // APNIC (Asia Pacific: China, Japan, Australia, India, etc.)
  apnic: [1, 14, 27, 36, 39, 42, 43, 49, 58, 59, 60, 61, 101, 103, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 133, 150, 153, 171, 175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223],
  // LACNIC (Latin America & Caribbean)
  lacnic: [45, 177, 179, 181, 186, 187, 189, 190, 191, 200, 201],
  // AFRINIC (Africa)
  afrinic: [41, 102, 105, 154, 196, 197],
  // US DoD / Military
  dod: [6, 11, 21, 22, 26, 29, 30, 33, 55, 214, 215]
};

// Known Autonomous Systems and Cloud Networks
const KNOWN_NETWORKS = [
  { prefix: '209.85.', name: 'Google Workspace Relay', country: 'Estados Unidos', flag: '🇺🇸', org: 'Google LLC' },
  { prefix: '64.233.', name: 'Google Cloud Services', country: 'Estados Unidos', flag: '🇺🇸', org: 'Google LLC' },
  { prefix: '66.102.', name: 'Google Relay', country: 'Estados Unidos', flag: '🇺🇸', org: 'Google LLC' },
  { prefix: '66.249.', name: 'Googlebot / Google Infrastructure', country: 'Estados Unidos', flag: '🇺🇸', org: 'Google LLC' },
  { prefix: '74.125.', name: 'Google Mail Servers', country: 'Estados Unidos', flag: '🇺🇸', org: 'Google LLC' },
  { prefix: '172.217.', name: 'Google LLC Anycast', country: 'Estados Unidos', flag: '🇺🇸', org: 'Google LLC' },
  { prefix: '142.250.', name: 'Google Worldwide Network', country: 'Estados Unidos', flag: '🇺🇸', org: 'Google LLC' },
  { prefix: '40.92.', name: 'Microsoft 365 Exchange Online', country: 'Estados Unidos', flag: '🇺🇸', org: 'Microsoft Corporation' },
  { prefix: '40.107.', name: 'Microsoft 365 Exchange Online', country: 'Estados Unidos', flag: '🇺🇸', org: 'Microsoft Corporation' },
  { prefix: '52.100.', name: 'Microsoft Azure / Outlook', country: 'Estados Unidos', flag: '🇺🇸', org: 'Microsoft Corporation' },
  { prefix: '104.47.', name: 'Microsoft Exchange Protection', country: 'Estados Unidos', flag: '🇺🇸', org: 'Microsoft Corporation' },
  { prefix: '20.', name: 'Microsoft Azure Cloud', country: 'Estados Unidos', flag: '🇺🇸', org: 'Microsoft Corporation' },
  { prefix: '13.107.', name: 'Microsoft Network', country: 'Estados Unidos', flag: '🇺🇸', org: 'Microsoft Corporation' },
  { prefix: '1.1.1.', name: 'Cloudflare DNS / Proxy', country: 'Global Anycast', flag: '🌐', org: 'Cloudflare Inc.' },
  { prefix: '104.16.', name: 'Cloudflare CDN / Proxy', country: 'Estados Unidos', flag: '🇺🇸', org: 'Cloudflare Inc.' },
  { prefix: '172.64.', name: 'Cloudflare CDN', country: 'Estados Unidos', flag: '🇺🇸', org: 'Cloudflare Inc.' },
  { prefix: '3.', name: 'Amazon AWS Cloud', country: 'Estados Unidos', flag: '🇺🇸', org: 'Amazon.com Inc.' },
  { prefix: '18.', name: 'Amazon AWS Cloud', country: 'Estados Unidos', flag: '🇺🇸', org: 'Amazon.com Inc.' },
  { prefix: '54.', name: 'Amazon AWS Cloud', country: 'Estados Unidos', flag: '🇺🇸', org: 'Amazon.com Inc.' },
  { prefix: '51.254.', name: 'OVHcloud Hosting', country: 'Francia', flag: '🇫🇷', org: 'OVH SAS' },
  { prefix: '178.32.', name: 'OVHcloud Datacenter', country: 'Francia', flag: '🇫🇷', org: 'OVH SAS' },
  { prefix: '88.198.', name: 'Hetzner Online', country: 'Alemania', flag: '🇩🇪', org: 'Hetzner Online GmbH' },
  { prefix: '144.76.', name: 'Hetzner Online', country: 'Alemania', flag: '🇩🇪', org: 'Hetzner Online GmbH' },
  { prefix: '80.58.', name: 'Telefónica de España', country: 'España', flag: '🇪🇸', org: 'Telefónica de España S.A.U.' },
  { prefix: '80.24.', name: 'Telefónica de España', country: 'España', flag: '🇪🇸', org: 'Telefónica de España S.A.U.' },
  { prefix: '213.4.', name: 'Telefónica de España', country: 'España', flag: '🇪🇸', org: 'Telefónica de España S.A.U.' },
  { prefix: '212.145.', name: 'Vodafone España', country: 'España', flag: '🇪🇸', org: 'Vodafone España S.A.U.' },
  { prefix: '87.216.', name: 'Vodafone España', country: 'España', flag: '🇪🇸', org: 'Vodafone España S.A.U.' },
  { prefix: '62.36.', name: 'Orange Espagne', country: 'España', flag: '🇪🇸', org: 'Orange Espagne S.A.U.' },
  { prefix: '85.48.', name: 'Orange Espagne', country: 'España', flag: '🇪🇸', org: 'Orange Espagne S.A.U.' },
  { prefix: '185.220.', name: 'Tor Exit Relay / Bulletproof Hosting', country: 'Alemania / Red Tor', flag: '🧅', org: 'Tor Network Exit Relay' }
];

class IpGeolocator {
  /**
   * Performs an instant 100% offline analysis of any IP address
   * @param {string} ip 
   * @returns {Object} Offline classification and regional location
   */
  static analyzeOffline(ip) {
    if (!ip || ip === 'No detectada' || ip === 'Desconocido') {
      return {
        ip: ip || 'N/A',
        isPrivate: false,
        scope: 'Desconocido',
        rir: 'N/A',
        country: 'No identificado',
        region: 'Desconocida',
        org: 'No identificado',
        flag: '❓',
        threatLevel: 'neutral'
      };
    }

    const cleanIp = ip.trim().replace(/[\[\]]/g, '');

    // Check Private / Reserved IPv4
    if (cleanIp.startsWith('10.') || cleanIp.startsWith('192.168.') || cleanIp.startsWith('127.') || cleanIp === '0.0.0.0') {
      return {
        ip: cleanIp,
        isPrivate: true,
        scope: 'Red Privada Local (RFC 1918)',
        rir: 'IANA Reservada',
        country: 'Red de Área Local (LAN)',
        region: 'Intranet / Servidor Interno',
        org: 'Infraestructura Local',
        flag: '🏠',
        threatLevel: 'low'
      };
    }

    if (cleanIp.startsWith('172.')) {
      const parts = cleanIp.split('.');
      if (parts.length >= 2) {
        const second = parseInt(parts[1], 10);
        if (second >= 16 && second <= 31) {
          return {
            ip: cleanIp,
            isPrivate: true,
            scope: 'Red Privada Local (RFC 1918)',
            rir: 'IANA Reservada',
            country: 'Red de Área Local (LAN)',
            region: 'Intranet / Servidor Interno',
            org: 'Infraestructura Local',
            flag: '🏠',
            threatLevel: 'low'
          };
        }
      }
    }

    if (cleanIp.startsWith('169.254.')) {
      return {
        ip: cleanIp,
        isPrivate: true,
        scope: 'Enlace Local / APIPA (RFC 3927)',
        rir: 'IANA Reservada',
        country: 'Sin Asignación Enrutable',
        region: 'Enlace Local',
        org: 'Autoconfiguración Local',
        flag: '🔌',
        threatLevel: 'low'
      };
    }

    if (cleanIp.startsWith('100.') && cleanIp.includes('.')) {
      const parts = cleanIp.split('.');
      const second = parseInt(parts[1], 10);
      if (second >= 64 && second <= 127) {
        return {
          ip: cleanIp,
          isPrivate: true,
          scope: 'CGNAT Operador (RFC 6598)',
          rir: 'IANA Carrier-Grade NAT',
          country: 'Red de Acceso ISP',
          region: 'Traducción de Direcciones Operador',
          org: 'CGNAT Proveedor',
          flag: '📡',
          threatLevel: 'low'
        };
      }
    }

    // Check Known Subnets
    for (const net of KNOWN_NETWORKS) {
      if (cleanIp.startsWith(net.prefix)) {
        return {
          ip: cleanIp,
          isPrivate: false,
          scope: 'Pública de Internet',
          rir: this.getRirByOctet(cleanIp),
          country: net.country,
          region: net.name,
          org: net.org,
          flag: net.flag,
          threatLevel: net.name.includes('Tor') ? 'high' : 'low'
        };
      }
    }

    // Match by First Octet to RIR
    const firstOctet = parseInt(cleanIp.split('.')[0], 10);
    const rirInfo = this.getRirInfo(firstOctet);

    return {
      ip: cleanIp,
      isPrivate: false,
      scope: 'Pública de Internet',
      rir: rirInfo.name,
      country: rirInfo.region,
      region: rirInfo.description,
      org: `Bloque asignado por ${rirInfo.short}`,
      flag: rirInfo.flag,
      threatLevel: 'medium'
    };
  }

  static getRirByOctet(ip) {
    const first = parseInt(ip.split('.')[0], 10);
    return this.getRirInfo(first).name;
  }

  static getRirInfo(firstOctet) {
    if (isNaN(firstOctet)) return { name: 'Desconocido', short: 'N/A', region: 'Desconocida', description: 'Registro no identificado', flag: '🌐' };

    if (RIR_MAP.ripe.includes(firstOctet)) {
      return { name: 'RIPE NCC', short: 'RIPE', region: 'Europa / Oriente Medio / Asia Central', description: 'Área RIPE (España, UE, etc.)', flag: '🇪🇺' };
    }
    if (RIR_MAP.arin.includes(firstOctet)) {
      return { name: 'ARIN', short: 'ARIN', region: 'Estados Unidos / Canadá', description: 'Norteamérica', flag: '🇺🇸' };
    }
    if (RIR_MAP.apnic.includes(firstOctet)) {
      return { name: 'APNIC', short: 'APNIC', region: 'Asia / Pacífico', description: 'Asia y Oceanía', flag: '🌏' };
    }
    if (RIR_MAP.lacnic.includes(firstOctet)) {
      return { name: 'LACNIC', short: 'LACNIC', region: 'Latinoamérica y el Caribe', description: 'América Latina', flag: '🌎' };
    }
    if (RIR_MAP.afrinic.includes(firstOctet)) {
      return { name: 'AFRINIC', short: 'AFRINIC', region: 'África', description: 'Continente Africano', flag: '🌍' };
    }
    if (RIR_MAP.dod.includes(firstOctet)) {
      return { name: 'US DoD / DISA', short: 'DoD', region: 'EE. UU. (Red Militar)', description: 'Departamento de Defensa EE. UU.', flag: '🛡️' };
    }

    return { name: 'Registro IANA', short: 'IANA', region: 'Global IANA', description: 'Bloque Global', flag: '🌐' };
  }

  static async lookupOnline(ip) {
    const cleanIp = ip.trim().replace(/[\[\]]/g, '');
    const offline = this.analyzeOffline(cleanIp);
    if (offline.isPrivate) {
      return {
        success: true,
        source: 'offline_private',
        ip: cleanIp,
        country: offline.country,
        region: offline.region,
        city: 'Red Local',
        isp: offline.org,
        org: offline.scope,
        asn: 'N/A (Privada)',
        lat: 0.0,
        lon: 0.0,
        flag: offline.flag,
        mapsUrl: '',
        virustotalUrl: `https://www.virustotal.com/gui/ip-address/${cleanIp}`,
        abuseipdbUrl: `https://www.abuseipdb.com/check/${cleanIp}`,
        threatLevel: 'low'
      };
    }

    try {
      const http = require('node:http');
      const fetchPromise = new Promise((resolve, reject) => {
        const req = http.get(`http://ip-api.com/json/${cleanIp}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query`, { timeout: 4000 }, (res) => {
          let raw = '';
          res.on('data', chunk => raw += chunk);
          res.on('end', () => {
            try {
              resolve(JSON.parse(raw));
            } catch (err) {
              reject(err);
            }
          });
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      });

      const data = await fetchPromise;
      if (data && data.status === 'success') {
        const country = data.country || offline.country;
        const code = data.countryCode || '';
        const flag = this.getFlagEmoji(code) || offline.flag;
        const lat = data.lat || 0.0;
        const lon = data.lon || 0.0;
        return {
          success: true,
          source: 'online_api',
          ip: cleanIp,
          country,
          countryCode: code,
          region: data.regionName || offline.region,
          city: data.city || 'No disponible',
          zip: data.zip || '',
          isp: data.isp || offline.org,
          org: data.org || offline.org,
          asn: data.as || 'N/A',
          lat,
          lon,
          flag,
          mapsUrl: (lat && lon) ? `https://www.google.com/maps?q=${lat},${lon}` : '',
          virustotalUrl: `https://www.virustotal.com/gui/ip-address/${cleanIp}`,
          abuseipdbUrl: `https://www.abuseipdb.com/check/${cleanIp}`,
          threatLevel: offline.threatLevel
        };
      }
    } catch (e) {
      // Return offline fallback
    }

    return {
      success: true,
      source: 'offline_fallback',
      ip: cleanIp,
      country: offline.country,
      region: offline.region,
      city: 'Ubicación regional RIR (Consulta online sin conexión)',
      isp: offline.org,
      org: offline.scope,
      asn: offline.rir,
      lat: 0.0,
      lon: 0.0,
      flag: offline.flag,
      mapsUrl: '',
      virustotalUrl: `https://www.virustotal.com/gui/ip-address/${cleanIp}`,
      abuseipdbUrl: `https://www.abuseipdb.com/check/${cleanIp}`,
      threatLevel: offline.threatLevel
    };
  }

  static getFlagEmoji(countryCode) {
    if (!countryCode || countryCode.length !== 2) return '🌐';
    try {
      const codePoints = countryCode
        .toUpperCase()
        .split('')
        .map(char => 127397 + char.charCodeAt(0));
      return String.fromCodePoint(...codePoints);
    } catch (e) {
      return '🌐';
    }
  }
}

module.exports = IpGeolocator;

