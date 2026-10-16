"""
MailScope Forensics - Servidor HTTP y API Forense en Python 3 Puro
100% Local, Privado y Seguro. Cero dependencias externas.
Soporta archivos .eml (RFC 5322) y .msg (Outlook CFBF OLE2).
"""
import sys
import os
import json
import sqlite3
import hashlib
import re
import uuid
import struct
import base64
import webbrowser
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
import email
from email import policy
from email.header import decode_header

try:
    from security.ip_geolocator import IpGeolocator
except ImportError:
    import sys
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from security.ip_geolocator import IpGeolocator

def normalize_raw_email(input_str):
    if not input_str:
        return ''
    text = input_str.replace('\ufeff', '').strip()

    # 1. Detect if it starts with Gmail 'Mostrar original' summary followed by real RFC 5322 headers
    rfc_start = re.search(r'\r?\n(?=(?:Delivered-To|Received|Return-Path|Authentication-Results|ARC-Seal|ARC-Authentication-Results|X-Google-Smtp-Source|MIME-Version|From|To|Subject|Date):)', text, re.I)
    if rfc_start:
        first_section = text[:rfc_start.start()]
        if re.search(r'(?:ID del mensaje|Message ID|Creado el|Created on|SPF:\s*PASS|DKIM:\s*\'?PASS|DMARC:\s*\'?PASS)', first_section, re.I):
            text = text[rfc_start.start():].strip()

    # 2. If user pasted ONLY the Gmail summary block (without headers below)
    if re.search(r'(?:ID del mensaje|Message ID|Creado el|Created on|SPF:\s*PASS|DKIM:\s*\'?PASS)', text, re.I) and not re.search(r'(?:Delivered-To|Received|Return-Path):', text, re.I):
        reconstructed = []
        spf_val = 'pass'
        dkim_val = 'pass'
        dmarc_val = 'pass'
        ip_val = ''
        for line in text.splitlines():
            tab_match = re.match(r'^([^:\t]+)[:\t]\s*(.*)$', line)
            if tab_match:
                k = tab_match.group(1).strip().lower()
                v = tab_match.group(2).strip()
                if 'id del mensaje' in k or 'message id' in k:
                    reconstructed.append(f"Message-ID: {v}")
                elif k in ('de', 'from') or k.startswith(('de ', 'from ')):
                    reconstructed.append(f"From: {v}")
                elif k in ('para', 'to') or k.startswith(('para ', 'to ')):
                    reconstructed.append(f"To: {v}")
                elif k in ('asunto', 'subject') or k.startswith(('asunto ', 'subject ')):
                    reconstructed.append(f"Subject: {v}")
                elif any(x in k for x in ('creado', 'created', 'fecha', 'date')):
                    reconstructed.append(f"Date: {v}")
                elif 'spf' in k:
                    ip_m = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', v)
                    if ip_m: ip_val = ip_m.group(0)
                    spf_val = 'pass' if 'pass' in v.lower() else ('fail' if 'fail' in v.lower() else 'neutral')
                elif 'dkim' in k:
                    dkim_val = 'pass' if 'pass' in v.lower() else 'fail'
                elif 'dmarc' in k:
                    dmarc_val = 'pass' if 'pass' in v.lower() else 'fail'
        if ip_val:
            reconstructed.append(f"Received: from mail.google.com ([{ip_val}]) by mx.google.com with ESMTPS;")
            reconstructed.append(f"Received-SPF: {spf_val} client-ip={ip_val};")
        reconstructed.append(f"Authentication-Results: mx.google.com; spf={spf_val} (client-ip={ip_val or '209.85.220.41'}); dkim={dkim_val}; dmarc={dmarc_val}")
        reconstructed.append("")
        reconstructed.append("(Contenido extraído del resumen de cabeceras de Gmail)")
        return "\r\n".join(reconstructed)

    # 3. Localized header aliases (Spanish web UI)
    lines = text.splitlines()
    norm = []
    in_hdr = True
    for line in lines:
        if in_hdr and not line.strip():
            in_hdr = False
        if in_hdr:
            line = re.sub(r'^(?:De|From)\s*:\s*', 'From: ', line, flags=re.I)
            line = re.sub(r'^(?:Para|To)\s*:\s*', 'To: ', line, flags=re.I)
            line = re.sub(r'^(?:Asunto|Subject)\s*:\s*', 'Subject: ', line, flags=re.I)
            line = re.sub(r'^(?:Fecha|Date)\s*:\s*', 'Date: ', line, flags=re.I)
            line = re.sub(r'^(?:Responder a|Reply-To)\s*:\s*', 'Reply-To: ', line, flags=re.I)
        norm.append(line)
    return "\r\n".join(norm)

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, 'public')
SAMPLES_DIR = os.path.join(BASE_DIR, 'samples')
DATA_DIR = os.path.join(BASE_DIR, 'data')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(SAMPLES_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, 'forensics.sqlite')

# =====================================================================
# 1. BASE DE DATOS SQLITE LOCAL
# =====================================================================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    with conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                subject TEXT,
                sender TEXT,
                recipient TEXT,
                origin_ip TEXT,
                spf_status TEXT,
                dkim_status TEXT,
                dmarc_status TEXT,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                attachments_count INTEGER DEFAULT 0,
                analysis_json TEXT NOT NULL
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_created ON analyses(created_at DESC)')
    conn.close()

init_db()

# =====================================================================
# 2. PARSERS FORENSES (.EML Y .MSG)
# =====================================================================
class EmailForensicParser:
    @staticmethod
    def decode_str(header_val):
        if not header_val:
            return ""
        decoded_parts = decode_header(header_val)
        result = []
        for part, enc in decoded_parts:
            if isinstance(part, bytes):
                enc_name = enc or 'utf-8'
                try:
                    result.append(part.decode(enc_name, errors='replace'))
                except Exception:
                    result.append(part.decode('latin1', errors='replace'))
            else:
                result.append(str(part))
        return "".join(result)

    @staticmethod
    def parse_address(addr_str):
        if not addr_str:
            return {"name": "", "address": "", "domain": "", "full": ""}
        clean = EmailForensicParser.decode_str(addr_str).strip()
        match = re.match(r'^(.*?)\s*<([^>]+)>', clean)
        if match:
            name = match.group(1).strip().strip('"\'')
            address = match.group(2).strip().lower()
            domain = address.split('@')[1] if '@' in address else ''
            return {"name": name, "address": address, "domain": domain, "full": clean}
        address = clean.strip('"\'<>').lower()
        domain = address.split('@')[1] if '@' in address else ''
        return {"name": address, "address": address, "domain": domain, "full": clean}

    @staticmethod
    def is_suspicious_ext(filename):
        if not filename:
            return False
        dangerous = (
            '.exe', '.dll', '.bat', '.cmd', '.scr', '.vbs', '.vbe', '.js',
            '.jse', '.wsf', '.wsh', '.hta', '.ps1', '.iso', '.img', '.docm',
            '.xlsm', '.pptm', '.pif', '.cpl', '.jar', '.com', '.reg', '.lnk'
        )
        return any(filename.lower().endswith(ext) for ext in dangerous)

    @classmethod
    def parse_eml(cls, raw_bytes):
        try:
            text_candidate = raw_bytes.decode('utf-8', errors='replace')
            normalized_text = normalize_raw_email(text_candidate)
            processed_bytes = normalized_text.encode('utf-8')
        except Exception:
            processed_bytes = raw_bytes

        msg = email.message_from_bytes(processed_bytes, policy=policy.default)
        
        # Headers collection
        headers_dict = {}
        raw_headers_list = []
        for k, v in msg.items():
            lk = k.lower()
            if lk not in headers_dict:
                headers_dict[lk] = []
            val_str = str(v)
            headers_dict[lk].append(val_str)
            raw_headers_list.append(f"{k}: {val_str}")
        
        raw_headers_text = "\r\n".join(raw_headers_list)
        
        subject = cls.decode_str(msg.get('Subject', '(Sin asunto)'))
        from_obj = cls.parse_address(msg.get('From', ''))
        
        to_header = msg.get('To', '')
        to_list = [cls.parse_address(x.strip()) for x in to_header.split(',') if x.strip()]
        
        cc_header = msg.get('Cc', '')
        cc_list = [cls.parse_address(x.strip()) for x in cc_header.split(',') if x.strip()]
        
        text_body = ""
        html_body = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disp = str(part.get('Content-Disposition', ''))
                filename = part.get_filename()

                if filename or 'attachment' in content_disp:
                    payload = part.get_payload(decode=True) or b''
                    safe_name = cls.decode_str(filename or 'adjunto')
                    attachments.append({
                        "filename": safe_name,
                        "contentType": content_type,
                        "size": len(payload),
                        "md5": hashlib.md5(payload).hexdigest(),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "dataBase64": base64.b64encode(payload).decode('ascii'),
                        "isSuspicious": cls.is_suspicious_ext(safe_name)
                    })
                else:
                    if content_type == 'text/plain' and not text_body:
                        payload = part.get_payload(decode=True) or b''
                        text_body = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
                    elif content_type == 'text/html' and not html_body:
                        payload = part.get_payload(decode=True) or b''
                        html_body = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
        else:
            payload = msg.get_payload(decode=True) or b''
            charset = msg.get_content_charset() or 'utf-8'
            decoded = payload.decode(charset, errors='replace')
            if msg.get_content_type() == 'text/html':
                html_body = decoded
            else:
                text_body = decoded

        return {
            "headers": headers_dict,
            "rawHeadersText": raw_headers_text,
            "subject": subject,
            "from": from_obj,
            "to": to_list,
            "cc": cc_list,
            "bcc": [],
            "date": msg.get('Date', ''),
            "messageId": msg.get('Message-ID', ''),
            "replyTo": cls.parse_address(msg.get('Reply-To', '')),
            "returnPath": msg.get('Return-Path', ''),
            "textBody": text_body,
            "htmlBody": html_body,
            "attachments": attachments,
            "size": len(raw_bytes)
        }

    @classmethod
    def parse_msg(cls, raw_bytes):
        # Verify CFBF Signature
        CFBF_SIG = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
        if not raw_bytes.startswith(CFBF_SIG):
            return cls.parse_eml(raw_bytes)

        # Parse OLE2 Compound Document
        sector_shift = struct.unpack_from('<H', raw_bytes, 30)[0]
        sector_size = 1 << sector_shift
        num_fat_sectors = struct.unpack_from('<I', raw_bytes, 44)[0]
        first_dir_sector = struct.unpack_from('<I', raw_bytes, 48)[0]

        fat_sectors = []
        for i in range(min(109, num_fat_sectors)):
            sec = struct.unpack_from('<I', raw_bytes, 76 + i * 4)[0]
            if sec <= 0xFFFFFFFA:
                fat_sectors.append(sec)

        fat = []
        for fsec in fat_sectors:
            off = (fsec + 1) * sector_size
            count = sector_size // 4
            for c in range(count):
                fat.append(struct.unpack_from('<I', raw_bytes, off + c * 4)[0])

        def read_chain(start_sec):
            chunks = []
            cur = start_sec
            guard = 0
            while cur <= 0xFFFFFFFA and guard < 100000:
                off = (cur + 1) * sector_size
                if off + sector_size <= len(raw_bytes):
                    chunks.append(raw_bytes[off:off + sector_size])
                cur = fat[cur] if cur < len(fat) else 0xFFFFFFFF
                guard += 1
            return b"".join(chunks)

        dir_data = read_chain(first_dir_sector)
        num_entries = len(dir_data) // 128
        
        transport_headers = ""
        subject = ""
        body = ""
        html_body = ""
        sender = ""
        display_to = ""
        attachments = []

        for i in range(num_entries):
            off = i * 128
            name_len = struct.unpack_from('<H', dir_data, off + 64)[0]
            if name_len <= 2:
                continue
            name_bytes = dir_data[off:off + name_len - 2]
            try:
                name = name_bytes.decode('utf-16le', errors='ignore')
            except Exception:
                continue
            
            entry_type = dir_data[off + 66]
            if entry_type != 2: # Stream
                continue
            
            start_sec = struct.unpack_from('<I', dir_data, off + 116)[0]
            stream_size = struct.unpack_from('<Q', dir_data, off + 120)[0]

            if name.startswith('__substg1.0_'):
                tag = name[12:16].upper()
                prop_type = name[16:20].upper()
                stream_content = read_chain(start_sec)[:stream_size]

                if tag == '007D': # PR_TRANSPORT_MESSAGE_HEADERS
                    transport_headers = stream_content.decode('utf-16le' if prop_type == '001F' else 'latin1', errors='replace')
                elif tag == '0037': # PR_SUBJECT
                    subject = stream_content.decode('utf-16le' if prop_type == '001F' else 'latin1', errors='replace')
                elif tag in ('0C1F', '0C1E') and not sender:
                    sender = stream_content.decode('utf-16le' if prop_type == '001F' else 'latin1', errors='replace')
                elif tag == '0E04': # PR_DISPLAY_TO
                    display_to = stream_content.decode('utf-16le' if prop_type == '001F' else 'latin1', errors='replace')
                elif tag == '1000': # PR_BODY
                    body = stream_content.decode('utf-16le' if prop_type == '001F' else 'latin1', errors='replace')
                elif tag == '1013': # PR_HTML
                    html_body = stream_content.decode('utf-8', errors='replace')
                elif tag == '3701': # PR_ATTACH_DATA_BIN
                    attachments.append({
                        "filename": "adjunto.dat",
                        "contentType": "application/octet-stream",
                        "size": len(stream_content),
                        "md5": hashlib.md5(stream_content).hexdigest(),
                        "sha256": hashlib.sha256(stream_content).hexdigest(),
                        "dataBase64": base64.b64encode(stream_content).decode('ascii'),
                        "isSuspicious": False
                    })
                elif tag in ('3707', '3704') and attachments:
                    fn = stream_content.decode('utf-16le' if prop_type == '001F' else 'latin1', errors='replace').strip('\x00\r\n')
                    attachments[-1]["filename"] = fn
                    attachments[-1]["isSuspicious"] = cls.is_suspicious_ext(fn)

        if transport_headers and transport_headers.strip():
            parsed = cls.parse_eml((transport_headers + "\r\n\r\n" + body).encode('utf-8', errors='replace'))
            if body and not parsed["textBody"]:
                parsed["textBody"] = body
            if html_body and not parsed["htmlBody"]:
                parsed["htmlBody"] = html_body
            if attachments:
                parsed["attachments"].extend(attachments)
            return parsed

        # Fallback if no transport headers
        return {
            "headers": {},
            "rawHeadersText": f"From: {sender}\r\nTo: {display_to}\r\nSubject: {subject}",
            "subject": subject or '(Sin asunto)',
            "from": cls.parse_address(sender),
            "to": [cls.parse_address(display_to)],
            "cc": [],
            "bcc": [],
            "date": "",
            "messageId": "",
            "replyTo": {"name": "", "address": "", "domain": "", "full": ""},
            "returnPath": "",
            "textBody": body,
            "htmlBody": html_body,
            "attachments": attachments,
            "size": len(raw_bytes)
        }

# =====================================================================
# 3. ANALIZADORES DE SEGURIDAD (SPF, DKIM, DMARC, RED Y RIESGO)
# =====================================================================
class SecurityEngine:
    @staticmethod
    def analyze_spf(headers, from_obj, return_path):
        received_spf = headers.get('received-spf', [])
        auth_results = headers.get('authentication-results', [])
        
        status = 'none'
        client_ip = None
        sender = None
        details = 'No se encontraron registros de evaluación SPF en las cabeceras.'
        
        # Check Received-SPF
        for rspf in received_spf:
            first_word = re.match(r'^([a-zA-Z]+)', rspf.strip())
            if first_word and status == 'none':
                status = first_word.group(1).lower()
            ip_m = re.search(r'client-ip=([0-9a-fA-F.:]+)', rspf, re.I) or re.search(r'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)', rspf)
            if ip_m and not client_ip:
                client_ip = ip_m.group(1)
            snd_m = re.search(r'envelope-from=([^\s;]+)', rspf, re.I) or re.search(r'domain of\s+([^\s;]+)', rspf, re.I)
            if snd_m and not sender:
                sender = snd_m.group(1).strip('<>')
            details = rspf

        # Check Authentication-Results
        for ares in auth_results:
            m = re.search(r'\bspf=([a-zA-Z]+)(?:\s*\(([^)]*)\))?', ares, re.I)
            if m:
                status = m.group(1).lower()
                if m.group(2):
                    details = m.group(2)
                if not client_ip:
                    ip_m = re.search(r'client-ip=([0-9a-fA-F.:]+)', ares, re.I) or re.search(r'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)', ares)
                    if ip_m:
                        client_ip = ip_m.group(1)
                if not sender:
                    snd_m = re.search(r'smtp\.mailfrom=([^\s;]+)', ares, re.I) or re.search(r'domain of\s+([^\s;]+)', ares, re.I)
                    if snd_m:
                        sender = snd_m.group(1).strip('<>')
                break

        domain = sender.split('@')[1] if sender and '@' in sender else sender
        if not domain and return_path and '@' in return_path:
            domain = return_path.strip('<>').split('@')[1]
        domain = (domain or 'No detectado').lower().strip('.')

        from_domain = (from_obj.get('domain') or '').lower().strip()
        is_aligned = False
        alignment_type = 'none'

        if from_domain and domain != 'no detectado':
            if from_domain == domain:
                is_aligned = True
                alignment_type = 'strict'
            elif from_domain.endswith('.' + domain) or domain.endswith('.' + from_domain):
                is_aligned = True
                alignment_type = 'relaxed'
            else:
                alignment_type = 'fail'

        level = 'warning'
        if status == 'pass':
            level = 'success' if is_aligned else 'warning'
            summary = 'SPF Válido y Alineado' if is_aligned else 'SPF Válido sin Alineación con el remitente visible'
        elif status == 'fail':
            level = 'danger'
            summary = 'SPF Fail (-all): La IP emisora NO está autorizada para emitir en nombre del dominio.'
        elif status == 'softfail':
            level = 'warning'
            summary = 'SPF Softfail (~all): La IP emisora probablemente no está autorizada.'
        else:
            level = 'warning' if status != 'none' else 'danger'
            summary = f'Estado SPF: {status.upper()}'

        return {
            "status": status,
            "securityLevel": level,
            "summaryText": summary,
            "clientIp": client_ip or 'No especificada',
            "sender": sender or return_path or 'Desconocido',
            "spfDomain": domain,
            "fromDomain": from_domain,
            "isAligned": is_aligned,
            "alignmentType": alignment_type,
            "details": details
        }

    @staticmethod
    def analyze_dkim(headers, from_obj):
        raw_sigs = headers.get('dkim-signature', [])
        auth_results = headers.get('authentication-results', [])
        from_domain = (from_obj.get('domain') or '').lower().strip()

        signatures = []
        for sig in raw_sigs:
            tags = {}
            for part in sig.split(';'):
                if '=' in part:
                    k, v = part.split('=', 1)
                    tags[k.strip().lower()] = v.strip()
            
            sign_domain = tags.get('d', '').lower().strip()
            is_aligned = False
            if from_domain and sign_domain:
                if from_domain == sign_domain or from_domain.endswith('.' + sign_domain) or sign_domain.endswith('.' + from_domain):
                    is_aligned = True
            
            is_weak = 'sha1' in tags.get('a', '').lower()
            signatures.append({
                "version": tags.get('v', '1'),
                "algorithm": tags.get('a', 'Desconocido'),
                "domain": sign_domain,
                "selector": tags.get('s', ''),
                "isAligned": is_aligned,
                "isWeakAlgo": is_weak,
                "raw": sig
            })

        auth_status = 'none'
        for ares in auth_results:
            m = re.search(r'\bdkim=([a-zA-Z]+)', ares, re.I)
            if m:
                auth_status = m.group(1).lower()
                break

        has_aligned = any(s["isAligned"] for s in signatures)
        final_status = auth_status if auth_status != 'none' else ('signed_unverified' if signatures else 'none')

        if final_status == 'pass':
            level = 'success' if has_aligned else 'warning'
            summary = 'DKIM Válido y Alineado criptográficamente.' if has_aligned else 'DKIM Válido por terceros (Sin alineación con From).'
        elif final_status == 'fail':
            level = 'danger'
            summary = 'Fallo Crítico DKIM: Firma digital inválida o mensaje alterado.'
        elif signatures:
            level = 'info'
            summary = f'Mensaje con {len(signatures)} firma(s) DKIM presente(s).'
        else:
            level = 'danger'
            summary = 'Sin Firma DKIM: El mensaje carece de protección criptográfica.'

        return {
            "status": final_status,
            "securityLevel": level,
            "summaryText": summary,
            "hasSignatures": len(signatures) > 0,
            "hasAlignedSignature": has_aligned,
            "signaturesCount": len(signatures),
            "signatures": signatures
        }

    @staticmethod
    def analyze_dmarc(headers, spf_res, dkim_res, from_obj):
        auth_results = headers.get('authentication-results', [])
        recorded_status = 'none'
        recorded_policy = 'none'

        for ares in auth_results:
            m = re.search(r'\bdmarc=([a-zA-Z]+)', ares, re.I)
            if m:
                recorded_status = m.group(1).lower()
                p_m = re.search(r'\bp=([a-zA-Z]+)', ares, re.I)
                if p_m:
                    recorded_policy = p_m.group(1).lower()
                break

        spf_pass_aligned = spf_res.get('status') == 'pass' and spf_res.get('isAligned')
        dkim_pass_aligned = dkim_res.get('status') in ('pass', 'signed_unverified') and dkim_res.get('hasAlignedSignature')

        computed_status = 'pass' if (spf_pass_aligned or dkim_pass_aligned) else 'fail'
        final_status = recorded_status if recorded_status != 'none' else computed_status

        level = 'success' if final_status == 'pass' else 'danger'
        summary = 'DMARC Aprobado (PASS): Autenticación y alineación correctas.' if final_status == 'pass' else 'DMARC Fallido (FAIL): Desalineación con el dominio emisor.'

        return {
            "status": final_status,
            "securityLevel": level,
            "summaryText": summary,
            "spfDmarcPass": spf_pass_aligned,
            "dkimDmarcPass": dkim_pass_aligned,
            "policy": recorded_policy,
            "policyExplanation": f"Política declarada por el dominio: {recorded_policy.upper()}"
        }

    @staticmethod
    def analyze_network(headers):
        raw_received = headers.get('received', [])
        chronological = list(reversed(raw_received))
        hops = []
        origin_ip = None
        origin_hop_idx = 1

        def is_private_ip(ip):
            if not ip: return False
            if ip.startswith(('10.', '127.', '192.168.', '0.0.0.0', '169.254.')): return True
            if ip.startswith('172.'):
                parts = ip.split('.')
                if len(parts) >= 2 and 16 <= int(parts[1]) <= 31: return True
            if ip in ('::1', '::') or ip.lower().startswith(('fe80:', 'fc00:')): return True
            return False

        for i, hop_str in enumerate(chronological, 1):
            clean = " ".join(hop_str.split())
            sender_host = "Desconocido"
            sender_ip = None

            from_m = re.search(r'\bfrom\s+([^\s(]+)(?:\s*\(([^)]*)\))?', clean, re.I)
            if from_m:
                sender_host = from_m.group(1)
                paren = from_m.group(2) or ''
                ip_in_p = re.search(r'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)', paren)
                if ip_in_p:
                    sender_ip = ip_in_p.group(1)

            if not sender_ip:
                all_ips = re.findall(r'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)', clean)
                if all_ips:
                    sender_ip = all_ips[0]

            by_m = re.search(r'\bby\s+([^\s(]+)', clean, re.I)
            receiver_host = by_m.group(1) if by_m else "Desconocido"

            with_m = re.search(r'\bwith\s+([^\s;]+)', clean, re.I)
            protocol = with_m.group(1) if with_m else "SMTP estándar"

            date_str = clean.split(';')[-1].strip() if ';' in clean else ''

            if not origin_ip and sender_ip and not is_private_ip(sender_ip):
                origin_ip = sender_ip
                origin_hop_idx = i

            hops.append({
                "hopNumber": i,
                "senderHost": sender_host,
                "senderIp": sender_ip,
                "receiverHost": receiver_host,
                "protocol": protocol,
                "dateFormatted": date_str,
                "delayFormatted": f"Salto {i}",
                "geo": IpGeolocator.analyze_offline(sender_ip) if sender_ip else None
            })

        if not origin_ip and hops:
            origin_ip = hops[0].get('senderIp') or 'No identificada'

        return {
            "totalHops": len(hops),
            "originIp": origin_ip or 'No detectada',
            "originHopIndex": origin_hop_idx,
            "isOriginPrivate": is_private_ip(origin_ip),
            "originGeo": IpGeolocator.analyze_offline(origin_ip),
            "totalTransitFormatted": f"{len(hops)} saltos",
            "hops": hops
        }

    @staticmethod
    def evaluate_risk(email_data, spf, dkim, dmarc, network):
        score = 0
        findings = []

        from_name = (email_data.get('from', {}).get('name') or '').lower()
        from_domain = (email_data.get('from', {}).get('domain') or '').lower()
        return_path = (email_data.get('returnPath') or '').lower()
        reply_to_domain = (email_data.get('replyTo', {}).get('domain') or '').lower()

        # 1. SPF
        if spf['status'] == 'fail':
            score += 35
            findings.append({"severity": "critical", "points": 35, "protocol": "SPF", "title": "Fallo SPF Crítico (-all)", "description": "La IP no tiene autorización para enviar en nombre del dominio."})
        elif spf['status'] == 'softfail':
            score += 20
            findings.append({"severity": "high", "points": 20, "protocol": "SPF", "title": "SPF Softfail (~all)", "description": "Envío probablemente no autorizado según la política SPF."})
        elif spf['status'] == 'none':
            score += 15
            findings.append({"severity": "medium", "points": 15, "protocol": "SPF", "title": "Sin Registro SPF", "description": "El dominio emisor no cuenta con directivas SPF activas."})

        if spf['status'] == 'pass' and not spf['isAligned']:
            score += 15
            findings.append({"severity": "medium", "points": 15, "protocol": "SPF", "title": "Desalineación SPF", "description": "El envelope sender no coincide con el dominio visible en From."})

        # 2. DKIM
        if dkim['status'] == 'fail':
            score += 35
            findings.append({"severity": "critical", "points": 35, "protocol": "DKIM", "title": "Firma DKIM Inválida / Corrupta", "description": "La firma criptográfica no es íntegra."})
        elif not dkim['hasSignatures']:
            score += 25
            findings.append({"severity": "high", "points": 25, "protocol": "DKIM", "title": "Ausencia de Firma DKIM", "description": "El mensaje no está firmado digitalmente."})

        # 3. DMARC
        if dmarc['status'] == 'fail':
            score += 30
            findings.append({"severity": "critical", "points": 30, "protocol": "DMARC", "title": "Fallo DMARC", "description": "El mensaje no supera las reglas de autenticación y alineación."})

        # 4. SPOOFING
        brands = [('google', 'google.'), ('microsoft', 'microsoft.'), ('apple', 'apple.'), ('paypal', 'paypal.'), ('santander', 'santander.'), ('bbva', 'bbva.')]
        for b_name, b_dom in brands:
            in_name = b_name in from_name
            in_dom = b_name in from_domain or b_dom in from_domain
            if in_name and not in_dom:
                score += 30
                findings.append({"severity": "critical", "points": 30, "protocol": "Identidad", "title": f"Display Name Spoofing ({b_name.upper()})", "description": f"El nombre visible suplanta a {b_name.upper()} con una dirección no autorizada ({from_domain})."})
                break
            if in_dom and (spf['status'] == 'fail' or dmarc['status'] == 'fail'):
                score += 30
                findings.append({"severity": "critical", "points": 30, "protocol": "Identidad", "title": f"Suplantación Directa de Marca ({b_name.upper()})", "description": f"El remitente afirma ser {from_domain} pero falla la autenticación criptográfica."})
                break

        # Return-Path vs From
        if return_path and '@' in return_path and from_domain:
            rp_dom = return_path.strip('<>').split('@')[1].lower()
            if rp_dom != from_domain and not from_domain.endswith('.' + rp_dom):
                score += 15
                findings.append({"severity": "medium", "points": 15, "protocol": "Identidad", "title": "Discrepancia From / Return-Path", "description": f"Las respuestas rebotarán hacia {rp_dom} y no hacia {from_domain}."})

        # Reply-To
        if reply_to_domain and from_domain and reply_to_domain != from_domain:
            score += 20
            findings.append({"severity": "high", "points": 20, "protocol": "Identidad", "title": "Desviación de Respuesta (Reply-To)", "description": f"Las respuestas serán dirigidas hacia {reply_to_domain}."})

        # Adjuntos peligrosos
        for att in email_data.get('attachments', []):
            if att.get('isSuspicious'):
                score += 40
                findings.append({"severity": "critical", "points": 40, "protocol": "Adjuntos", "title": f"Adjunto Peligroso ({att['filename']})", "description": "Contiene un archivo ejecutable o script malicioso."})

        final_score = min(100, max(0, score))
        if final_score >= 80:
            level, label, color = 'critical', 'Riesgo Crítico (Malicioso)', '#ef4444'
        elif final_score >= 51:
            level, label, color = 'high', 'Alto Riesgo (Sospechoso)', '#f97316'
        elif final_score >= 21:
            level, label, color = 'medium', 'Riesgo Moderado (Precaución)', '#f59e0b'
        else:
            level, label, color = 'low', 'Bajo Riesgo (Seguro)', '#10b981'

        return {
            "score": final_score,
            "level": level,
            "label": label,
            "color": color,
            "findings": findings
        }

# =====================================================================
# 4. SERVIDOR HTTP Y API REST
# =====================================================================
def run_full_analysis(raw_bytes, filename="correo.eml"):
    is_msg = raw_bytes.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1') or filename.lower().endswith('.msg')
    if is_msg:
        email_data = EmailForensicParser.parse_msg(raw_bytes)
    else:
        email_data = EmailForensicParser.parse_eml(raw_bytes)

    spf = SecurityEngine.analyze_spf(email_data['headers'], email_data['from'], email_data['returnPath'])
    dkim = SecurityEngine.analyze_dkim(email_data['headers'], email_data['from'])
    dmarc = SecurityEngine.analyze_dmarc(email_data['headers'], spf, dkim, email_data['from'])
    network = SecurityEngine.analyze_network(email_data['headers'])
    risk = SecurityEngine.evaluate_risk(email_data, spf, dkim, dmarc, network)

    analysis_id = str(uuid.uuid4())
    result = {
        "id": analysis_id,
        "filename": filename,
        "fileType": "msg" if is_msg else "eml",
        "fileSize": len(raw_bytes),
        "analyzedAt": datetime.now(timezone.utc).isoformat(),
        "email": email_data,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "network": network,
        "risk": risk
    }

    # Save to SQLite
    try:
        conn = get_db()
        with conn:
            conn.execute('''
                INSERT INTO analyses (
                    id, created_at, filename, file_type, file_size, subject,
                    sender, recipient, origin_ip, spf_status, dkim_status,
                    dmarc_status, risk_score, risk_level, attachments_count, analysis_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis_id, result["analyzedAt"], filename, result["fileType"],
                len(raw_bytes), email_data["subject"], email_data["from"]["address"],
                ", ".join(t["address"] for t in email_data["to"]),
                network["originIp"], spf["status"], dkim["status"],
                dmarc["status"], risk["score"], risk["level"],
                len(email_data["attachments"]), json.dumps(result)
            ))
        conn.close()
    except Exception as e:
        print("[DB Error]:", e)

    return result

class ForensicRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PUBLIC_DIR, **kwargs)

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/api/samples':
            samples = []
            if os.path.exists(SAMPLES_DIR):
                for f in os.listdir(SAMPLES_DIR):
                    p = os.path.join(SAMPLES_DIR, f)
                    if os.path.isfile(p) and (f.endswith('.eml') or f.endswith('.msg')):
                        samples.append({"name": f, "size": os.path.getsize(p), "type": "msg" if f.endswith('.msg') else "eml"})
            self.send_json({"success": True, "data": samples})
            return

        if path == '/api/history':
            params = parse_qs(parsed.query)
            q = params.get('q', [''])[0].strip().lower()
            conn = get_db()
            cursor = conn.cursor()
            if q:
                cursor.execute('''
                    SELECT id, created_at, filename, file_type, file_size, subject,
                           sender, recipient, origin_ip, spf_status, dkim_status,
                           dmarc_status, risk_score, risk_level, attachments_count
                    FROM analyses
                    WHERE lower(subject) LIKE ? OR lower(sender) LIKE ? OR origin_ip LIKE ?
                    ORDER BY created_at DESC LIMIT 50
                ''', (f'%{q}%', f'%{q}%', f'%{q}%'))
            else:
                cursor.execute('''
                    SELECT id, created_at, filename, file_type, file_size, subject,
                           sender, recipient, origin_ip, spf_status, dkim_status,
                           dmarc_status, risk_score, risk_level, attachments_count
                    FROM analyses
                    ORDER BY created_at DESC LIMIT 50
                ''')
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            self.send_json({"success": True, "data": rows})
            return

        if path.startswith('/api/history/'):
            item_id = path[len('/api/history/'):]
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT analysis_json FROM analyses WHERE id = ?', (item_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                self.send_json({"success": True, "data": json.loads(row['analysis_json'])})
            else:
                self.send_error(404, "Análisis no encontrado")
            return

        if path == '/api/geolocate':
            params = parse_qs(parsed.query)
            ip = params.get('ip', [''])[0].strip()
            if not ip:
                self.send_json({"success": False, "error": "Parámetro 'ip' requerido."}, status=400)
                return
            geo_result = IpGeolocator.lookup_online(ip)
            self.send_json({"success": True, "data": geo_result})
            return

        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        if path == '/api/analyze':
            try:
                content_type = self.headers.get('Content-Type', '')
                if 'application/json' in content_type:
                    payload = json.loads(body.decode('utf-8'))
                    if 'rawText' in payload and payload['rawText']:
                        raw_bytes = payload['rawText'].encode('utf-8')
                        filename = payload.get('filename', 'correo_texto_plano.eml')
                    elif 'base64' in payload and payload['base64']:
                        raw_bytes = base64.b64decode(payload['base64'])
                        filename = payload.get('filename', 'correo.eml')
                    else:
                        raise ValueError("No se enviaron datos de correo (base64 o rawText).")
                else:
                    raw_bytes = body
                    filename = self.headers.get('X-Filename', 'correo.eml')
                
                result = run_full_analysis(raw_bytes, filename)
                self.send_json({"success": True, "data": result})
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, status=500)
            return

        if path.startswith('/api/samples/'):
            sample_name = unquote(path[len('/api/samples/'):])
            sample_path = os.path.join(SAMPLES_DIR, sample_name)
            if not os.path.exists(sample_path):
                self.send_error(404, "Muestra no encontrada")
                return
            with open(sample_path, 'rb') as f:
                raw_bytes = f.read()
            result = run_full_analysis(raw_bytes, sample_name)
            self.send_json({"success": True, "data": result})
            return

        self.send_error(404, "Ruta no encontrada")

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith('/api/history/'):
            item_id = path[len('/api/history/'):]
            conn = get_db()
            with conn:
                conn.execute('DELETE FROM analyses WHERE id = ?', (item_id,))
            conn.close()
            self.send_json({"success": True, "message": "Eliminado"})
            return
        self.send_error(404)

    def send_json(self, data, status=200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def start_server():
    port = 8080
    server = None
    while port < 8150:
        try:
            server = HTTPServer(('127.0.0.1', port), ForensicRequestHandler)
            break
        except OSError:
            port += 1

    if not server:
        print("[ERROR] No se pudo vincular a ningún puerto disponible.")
        sys.exit(1)

    url = f"http://127.0.0.1:{port}"
    print("\n=============================================================")
    print("  MAILSCOPE FORENSICS - SERVIDOR ACTIVO EN:")
    print(f"  -> {url}")
    print("=============================================================\n")

    # Abrir navegador automáticamente
    def open_browser():
        try:
            webbrowser.open(url)
        except Exception:
            pass
    threading.Timer(1.2, open_browser).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido por el usuario.")
        server.server_close()

if __name__ == '__main__':
    start_server()
