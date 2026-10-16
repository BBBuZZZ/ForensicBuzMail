import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server import run_full_analysis
from security.ip_geolocator import IpGeolocator

# Case A: Full Gmail "Mostrar original" with summary table
case_a = """ID del mensaje\t<CA+G6_x8Z-7y@mail.google.com>
Creado el:\t14 de octubre de 2026, 17:30
De:\tGoogle Security Alert <noreply-security@google.com>
Para:\trecipient@mycompany.org
Asunto:\tAlerta de seguridad para tu cuenta de Google
SPF:\tPASS con la IP 209.85.220.41 Más información

Delivered-To: recipient@mycompany.org
Received: by 2002:a05:6808:1484:0:0:0:0 with SMTP id e4csp1287930oiw;
From: "Google Security Alert" <noreply-security@google.com>
To: recipient@mycompany.org
Subject: Alerta de seguridad para tu cuenta de Google

Cuerpo de prueba"""

res_a = run_full_analysis(case_a.encode('utf-8'), 'case_a.eml')
print("Case A (Gmail Mostrar original completo):")
print("  Subject:", res_a['email']['subject'])
print("  From:", res_a['email']['from']['address'])
print("  Hops:", res_a['network']['totalHops'])
assert res_a['email']['subject'] == "Alerta de seguridad para tu cuenta de Google"
assert res_a['email']['from']['address'] == "noreply-security@google.com"

# Case B: ONLY Gmail summary table
case_b = """ID del mensaje\t<CA+G6_x8Z-7y@mail.google.com>
Creado el:\t14 de octubre de 2026, 17:30
De:\tGoogle Security Alert <noreply-security@google.com>
Para:\trecipient@mycompany.org
Asunto:\tAlerta de seguridad para tu cuenta de Google
SPF:\tPASS con la IP 209.85.220.41 Más información
DKIM:\t'PASS' con el dominio google.com Más información
DMARC:\t'PASS' Más información"""

res_b = run_full_analysis(case_b.encode('utf-8'), 'case_b.eml')
print("\nCase B (SOLO tabla resumen de Gmail):")
print("  Subject:", res_b['email']['subject'])
print("  From:", res_b['email']['from']['address'])
print("  SPF:", res_b['spf']['status'], "| IP:", res_b['spf']['clientIp'])
print("  DKIM:", res_b['dkim']['status'])
print("  DMARC:", res_b['dmarc']['status'])
assert res_b['spf']['status'] == 'pass'
assert res_b['dkim']['status'] == 'pass'
assert res_b['dmarc']['status'] == 'pass'

# Case C: Gmail standard web copy (Spanish De/Para/Asunto)
case_c = """De: Alerta Banco <seguridad@bancofake.com>
Para: victima@correo.com
Asunto: Urgente verificar acceso
Fecha: 16 de oct de 2026, 08:30

Estimado cliente verifique sus datos."""

res_c = run_full_analysis(case_c.encode('utf-8'), 'case_c.eml')
print("\nCase C (Copiado de interfaz web Gmail en español):")
print("  Subject:", res_c['email']['subject'])
print("  From:", res_c['email']['from']['address'])
print("  Score:", res_c['risk']['score'])
assert res_c['email']['subject'] == "Urgente verificar acceso"
assert res_c['email']['from']['address'] == "seguridad@bancofake.com"

# Case D: Offline Geolocation check
print("\nCase D (Geolocalización Offline):")
geo_google = IpGeolocator.analyze_offline("209.85.220.41")
print("  Google IP 209.85.220.41 ->", geo_google['flag'], geo_google['country'], "| Org:", geo_google['org'])
assert "Google" in geo_google['org']

geo_lan = IpGeolocator.analyze_offline("192.168.1.100")
print("  LAN IP 192.168.1.100 ->", geo_lan['flag'], geo_lan['scope'])
assert geo_lan['isPrivate'] == True

geo_es = IpGeolocator.analyze_offline("80.58.61.250")
print("  Telefónica IP 80.58.61.250 ->", geo_es['flag'], geo_es['country'], "| Org:", geo_es['org'])
assert "Telefónica" in geo_es['org']

print("\n¡TODAS LAS PRUEBAS AUTOMATIZADAS PASARON SATISFACTORIAMENTE!")

