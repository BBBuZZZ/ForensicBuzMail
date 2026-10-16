"""
IP Geolocation Engine (Offline RIR / Subnet Database + Online API Lookup)
Part of ForensicBuzMail.
100% Zero external dependencies.
"""
import re
import json
import urllib.request
import urllib.error

# Offline IANA IPv4 Allocation Table to Regional Internet Registries (RIRs)
RIR_MAP = {
    'ripe': [2, 5, 24, 25, 31, 37, 46, 51, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 109, 141, 145, 147, 149, 151, 176, 178, 185, 188, 193, 194, 195, 212, 213, 217],
    'arin': [3, 4, 6, 7, 8, 9, 11, 12, 13, 15, 16, 17, 18, 19, 20, 23, 26, 32, 34, 35, 38, 40, 44, 47, 50, 52, 54, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 96, 97, 98, 99, 100, 104, 107, 108, 128, 129, 130, 131, 132, 134, 135, 136, 137, 138, 139, 140, 142, 143, 144, 146, 148, 152, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 172, 173, 174, 184, 192, 198, 199, 204, 205, 206, 207, 208, 209, 216],
    'apnic': [1, 14, 27, 36, 39, 42, 43, 49, 58, 59, 60, 61, 101, 103, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 133, 150, 153, 171, 175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223],
    'lacnic': [45, 177, 179, 181, 186, 187, 189, 190, 191, 200, 201],
    'afrinic': [41, 102, 105, 154, 196, 197],
    'dod': [6, 11, 21, 22, 26, 29, 30, 33, 55, 214, 215]
}

KNOWN_NETWORKS = [
    {'prefix': '209.85.', 'name': 'Google Workspace Relay', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Google LLC'},
    {'prefix': '64.233.', 'name': 'Google Cloud Services', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Google LLC'},
    {'prefix': '66.102.', 'name': 'Google Relay', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Google LLC'},
    {'prefix': '66.249.', 'name': 'Googlebot / Google Infrastructure', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Google LLC'},
    {'prefix': '74.125.', 'name': 'Google Mail Servers', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Google LLC'},
    {'prefix': '172.217.', 'name': 'Google LLC Anycast', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Google LLC'},
    {'prefix': '142.250.', 'name': 'Google Worldwide Network', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Google LLC'},
    {'prefix': '40.92.', 'name': 'Microsoft 365 Exchange Online', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Microsoft Corporation'},
    {'prefix': '40.107.', 'name': 'Microsoft 365 Exchange Online', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Microsoft Corporation'},
    {'prefix': '52.100.', 'name': 'Microsoft Azure / Outlook', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Microsoft Corporation'},
    {'prefix': '104.47.', 'name': 'Microsoft Exchange Protection', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Microsoft Corporation'},
    {'prefix': '20.', 'name': 'Microsoft Azure Cloud', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Microsoft Corporation'},
    {'prefix': '13.107.', 'name': 'Microsoft Network', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Microsoft Corporation'},
    {'prefix': '1.1.1.', 'name': 'Cloudflare DNS / Proxy', 'country': 'Global Anycast', 'flag': '🌐', 'org': 'Cloudflare Inc.'},
    {'prefix': '104.16.', 'name': 'Cloudflare CDN / Proxy', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Cloudflare Inc.'},
    {'prefix': '172.64.', 'name': 'Cloudflare CDN', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Cloudflare Inc.'},
    {'prefix': '3.', 'name': 'Amazon AWS Cloud', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Amazon.com Inc.'},
    {'prefix': '18.', 'name': 'Amazon AWS Cloud', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Amazon.com Inc.'},
    {'prefix': '54.', 'name': 'Amazon AWS Cloud', 'country': 'Estados Unidos', 'flag': '🇺🇸', 'org': 'Amazon.com Inc.'},
    {'prefix': '51.254.', 'name': 'OVHcloud Hosting', 'country': 'Francia', 'flag': '🇫🇷', 'org': 'OVH SAS'},
    {'prefix': '178.32.', 'name': 'OVHcloud Datacenter', 'country': 'Francia', 'flag': '🇫🇷', 'org': 'OVH SAS'},
    {'prefix': '88.198.', 'name': 'Hetzner Online', 'country': 'Alemania', 'flag': '🇩🇪', 'org': 'Hetzner Online GmbH'},
    {'prefix': '144.76.', 'name': 'Hetzner Online', 'country': 'Alemania', 'flag': '🇩🇪', 'org': 'Hetzner Online GmbH'},
    {'prefix': '80.58.', 'name': 'Telefónica de España', 'country': 'España', 'flag': '🇪🇸', 'org': 'Telefónica de España S.A.U.'},
    {'prefix': '80.24.', 'name': 'Telefónica de España', 'country': 'España', 'flag': '🇪🇸', 'org': 'Telefónica de España S.A.U.'},
    {'prefix': '213.4.', 'name': 'Telefónica de España', 'country': 'España', 'flag': '🇪🇸', 'org': 'Telefónica de España S.A.U.'},
    {'prefix': '212.145.', 'name': 'Vodafone España', 'country': 'España', 'flag': '🇪🇸', 'org': 'Vodafone España S.A.U.'},
    {'prefix': '87.216.', 'name': 'Vodafone España', 'country': 'España', 'flag': '🇪🇸', 'org': 'Vodafone España S.A.U.'},
    {'prefix': '62.36.', 'name': 'Orange Espagne', 'country': 'España', 'flag': '🇪🇸', 'org': 'Orange Espagne S.A.U.'},
    {'prefix': '85.48.', 'name': 'Orange Espagne', 'country': 'España', 'flag': '🇪🇸', 'org': 'Orange Espagne S.A.U.'},
    {'prefix': '185.220.', 'name': 'Tor Exit Relay / Bulletproof Hosting', 'country': 'Alemania / Red Tor', 'flag': '🧅', 'org': 'Tor Network Exit Relay'}
]

class IpGeolocator:
    @classmethod
    def analyze_offline(cls, ip):
        """
        Performs an instant 100% offline analysis of any IP address.
        """
        if not ip or ip in ('No detectada', 'Desconocido', 'No identificada', 'N/A'):
            return {
                'ip': ip or 'N/A',
                'isPrivate': False,
                'scope': 'Desconocido',
                'rir': 'N/A',
                'country': 'No identificado',
                'region': 'Desconocida',
                'org': 'No identificado',
                'flag': '❓',
                'threatLevel': 'neutral'
            }

        clean_ip = ip.strip().replace('[', '').replace(']', '')

        # Private / Loopback IPv4
        if clean_ip.startswith(('10.', '192.168.', '127.', '0.0.0.0')):
            return {
                'ip': clean_ip,
                'isPrivate': True,
                'scope': 'Red Privada Local (RFC 1918)',
                'rir': 'IANA Reservada',
                'country': 'Red de Área Local (LAN)',
                'region': 'Intranet / Servidor Interno',
                'org': 'Infraestructura Local',
                'flag': '🏠',
                'threatLevel': 'low'
            }

        if clean_ip.startswith('172.'):
            parts = clean_ip.split('.')
            if len(parts) >= 2:
                try:
                    second = int(parts[1])
                    if 16 <= second <= 31:
                        return {
                            'ip': clean_ip,
                            'isPrivate': True,
                            'scope': 'Red Privada Local (RFC 1918)',
                            'rir': 'IANA Reservada',
                            'country': 'Red de Área Local (LAN)',
                            'region': 'Intranet / Servidor Interno',
                            'org': 'Infraestructura Local',
                            'flag': '🏠',
                            'threatLevel': 'low'
                        }
                except ValueError:
                    pass

        if clean_ip.startswith('169.254.'):
            return {
                'ip': clean_ip,
                'isPrivate': True,
                'scope': 'Enlace Local / APIPA (RFC 3927)',
                'rir': 'IANA Reservada',
                'country': 'Sin Asignación Enrutable',
                'region': 'Enlace Local',
                'org': 'Autoconfiguración Local',
                'flag': '🔌',
                'threatLevel': 'low'
            }

        if clean_ip.startswith('100.'):
            parts = clean_ip.split('.')
            if len(parts) >= 2:
                try:
                    second = int(parts[1])
                    if 64 <= second <= 127:
                        return {
                            'ip': clean_ip,
                            'isPrivate': True,
                            'scope': 'CGNAT Operador (RFC 6598)',
                            'rir': 'IANA Carrier-Grade NAT',
                            'country': 'Red de Acceso ISP',
                            'region': 'Traducción de Direcciones Operador',
                            'org': 'CGNAT Proveedor',
                            'flag': '📡',
                            'threatLevel': 'low'
                        }
                except ValueError:
                    pass

        # IPv6 Loopback / Link-Local
        if clean_ip in ('::1', '::') or clean_ip.lower().startswith(('fe80:', 'fc00:')):
            return {
                'ip': clean_ip,
                'isPrivate': True,
                'scope': 'IPv6 Local / Reservada',
                'rir': 'IANA IPv6',
                'country': 'Red Local IPv6',
                'region': 'Enlace Local / Loopback',
                'org': 'Infraestructura Local IPv6',
                'flag': '🏠',
                'threatLevel': 'low'
            }

        # Known Cloud / Mail Subnets
        for net in KNOWN_NETWORKS:
            if clean_ip.startswith(net['prefix']):
                return {
                    'ip': clean_ip,
                    'isPrivate': False,
                    'scope': 'Pública de Internet',
                    'rir': cls.get_rir_by_octet(clean_ip),
                    'country': net['country'],
                    'region': net['name'],
                    'org': net['org'],
                    'flag': net['flag'],
                    'threatLevel': 'high' if 'Tor' in net['name'] else 'low'
                }

        # Match First Octet to RIR
        try:
            first_octet = int(clean_ip.split('.')[0])
            rir_info = cls.get_rir_info(first_octet)
            return {
                'ip': clean_ip,
                'isPrivate': False,
                'scope': 'Pública de Internet',
                'rir': rir_info['name'],
                'country': rir_info['region'],
                'region': rir_info['description'],
                'org': f"Bloque asignado por {rir_info['short']}",
                'flag': rir_info['flag'],
                'threatLevel': 'medium'
            }
        except Exception:
            return {
                'ip': clean_ip,
                'isPrivate': False,
                'scope': 'Pública de Internet',
                'rir': 'RIR Global',
                'country': 'Internacional',
                'region': 'Desconocida',
                'org': 'No identificado',
                'flag': '🌐',
                'threatLevel': 'medium'
            }

    @classmethod
    def get_rir_by_octet(cls, ip):
        try:
            first = int(ip.split('.')[0])
            return cls.get_rir_info(first)['name']
        except Exception:
            return 'RIR Global'

    @classmethod
    def get_rir_info(cls, first_octet):
        if first_octet in RIR_MAP['ripe']:
            return {'name': 'RIPE NCC', 'short': 'RIPE', 'region': 'Europa / España / Oriente Medio', 'description': 'Área RIPE (España, UE, etc.)', 'flag': '🇪🇺'}
        if first_octet in RIR_MAP['arin']:
            return {'name': 'ARIN', 'short': 'ARIN', 'region': 'Estados Unidos / Canadá', 'description': 'Norteamérica', 'flag': '🇺🇸'}
        if first_octet in RIR_MAP['apnic']:
            return {'name': 'APNIC', 'short': 'APNIC', 'region': 'Asia / Pacífico', 'description': 'Asia y Oceanía', 'flag': '🌏'}
        if first_octet in RIR_MAP['lacnic']:
            return {'name': 'LACNIC', 'short': 'LACNIC', 'region': 'Latinoamérica y el Caribe', 'description': 'América Latina', 'flag': '🌎'}
        if first_octet in RIR_MAP['afrinic']:
            return {'name': 'AFRINIC', 'short': 'AFRINIC', 'region': 'África', 'description': 'Continente Africano', 'flag': '🌍'}
        if first_octet in RIR_MAP['dod']:
            return {'name': 'US DoD / DISA', 'short': 'DoD', 'region': 'EE. UU. (Red Militar)', 'description': 'Departamento de Defensa EE. UU.', 'flag': '🛡️'}

        return {'name': 'Registro IANA', 'short': 'IANA', 'region': 'Global IANA', 'description': 'Bloque Global', 'flag': '🌐'}

    @classmethod
    def lookup_online(cls, ip):
        """
        Queries an external public geolocation API on demand when authorized by user.
        """
        clean_ip = ip.strip().replace('[', '').replace(']', '')
        # Fallback to offline if private
        offline = cls.analyze_offline(clean_ip)
        if offline['isPrivate']:
            return {
                'success': True,
                'source': 'offline_private',
                'ip': clean_ip,
                'country': offline['country'],
                'region': offline['region'],
                'city': 'Red Local',
                'isp': offline['org'],
                'org': offline['scope'],
                'asn': 'N/A (Privada)',
                'lat': 0.0,
                'lon': 0.0,
                'flag': offline['flag'],
                'mapsUrl': '',
                'threatLevel': 'low'
            }

        url = f"http://ip-api.com/json/{clean_ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        req = urllib.request.Request(url, headers={'User-Agent': 'ForensicBuzMail/2.0'})
        try:
            with urllib.request.urlopen(req, timeout=4) as response:
                data = json.loads(response.read().decode('utf-8'))
                if data.get('status') == 'success':
                    country = data.get('country', offline['country'])
                    code = data.get('countryCode', '')
                    flag = cls.get_flag_emoji(code) if code else offline['flag']
                    lat = data.get('lat', 0.0)
                    lon = data.get('lon', 0.0)
                    maps_url = f"https://www.google.com/maps?q={lat},{lon}" if lat and lon else ""
                    return {
                        'success': True,
                        'source': 'online_api',
                        'ip': clean_ip,
                        'country': country,
                        'countryCode': code,
                        'region': data.get('regionName', offline['region']),
                        'city': data.get('city', 'No disponible'),
                        'zip': data.get('zip', ''),
                        'isp': data.get('isp', offline['org']),
                        'org': data.get('org', offline['org']),
                        'asn': data.get('as', 'N/A'),
                        'lat': lat,
                        'lon': lon,
                        'flag': flag,
                        'mapsUrl': maps_url,
                        'virustotalUrl': f"https://www.virustotal.com/gui/ip-address/{clean_ip}",
                        'abuseipdbUrl': f"https://www.abuseipdb.com/check/{clean_ip}",
                        'threatLevel': offline['threatLevel']
                    }
        except Exception as e:
            # Return offline data enriched with notice
            pass

        return {
            'success': True,
            'source': 'offline_fallback',
            'ip': clean_ip,
            'country': offline['country'],
            'region': offline['region'],
            'city': 'Ubicación regional RIR (Consulta online sin conexión)',
            'isp': offline['org'],
            'org': offline['scope'],
            'asn': offline['rir'],
            'lat': 0.0,
            'lon': 0.0,
            'flag': offline['flag'],
            'mapsUrl': '',
            'virustotalUrl': f"https://www.virustotal.com/gui/ip-address/{clean_ip}",
            'abuseipdbUrl': f"https://www.abuseipdb.com/check/{clean_ip}",
            'threatLevel': offline['threatLevel']
        }

    @staticmethod
    def get_flag_emoji(country_code):
        if not country_code or len(country_code) != 2:
            return '🌐'
        try:
            return chr(ord(country_code[0].upper()) + 127397) + chr(ord(country_code[1].upper()) + 127397)
        except Exception:
            return '🌐'

