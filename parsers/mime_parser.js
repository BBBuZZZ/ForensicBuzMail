/**
 * RFC 5322 & MIME (RFC 2045-2049) Email Parser
 * Fully local, secure, zero-dependency parser for .eml files.
 */
const crypto = require('node:crypto');

class MimeParser {
  /**
   * Normalize Gmail and localized raw email pastes
   */
  static normalizeRawEmail(inputStr) {
    if (!inputStr) return '';
    let text = inputStr.replace(/\ufeff/g, '').trim();

    // Fast path: If the text is standard RFC 5322 and does NOT have Gmail summary artifacts or Spanish headers, return as-is
    const hasGmailArtifacts = /(?:ID del mensaje|Message ID|Creado el|Created on|SPF:\s*PASS|DKIM:\s*'?PASS|DMARC:\s*'?PASS)/i.test(text);
    const hasSpanishHeaders = /^(?:De|Para|Asunto|Fecha|Responder a)\s*:/im.test(text);
    if (!hasGmailArtifacts && !hasSpanishHeaders) {
      return text;
    }

    // 1. Detect if it starts with Gmail 'Mostrar original' summary followed by real headers
    const rfcStart = text.match(/\r?\n(?=(?:Delivered-To|Received|Return-Path|Authentication-Results|ARC-Seal|ARC-Authentication-Results|X-Google-Smtp-Source|MIME-Version|From|To|Subject|Date):)/i);
    if (rfcStart) {
      const firstSection = text.slice(0, rfcStart.index);
      if (/(?:ID del mensaje|Message ID|Creado el|Created on|SPF:\s*PASS|DKIM:\s*'?PASS|DMARC:\s*'?PASS)/i.test(firstSection)) {
        text = text.slice(rfcStart.index).trim();
      }
    }

    // 2. If user pasted ONLY the Gmail summary block (without headers below)
    if (/(?:ID del mensaje|Message ID|Creado el|Created on|SPF:\s*PASS|DKIM:\s*'?PASS)/i.test(text) && !/(?:Delivered-To|Received|Return-Path):/i.test(text)) {
      const reconstructed = [];
      let spfVal = 'pass';
      let dkimVal = 'pass';
      let dmarcVal = 'pass';
      let ipVal = '';
      const lines = text.split(/\r?\n/);
      for (const line of lines) {
        const tabMatch = line.match(/^([^:\t]+)[:\t]\s*(.*)$/);
        if (tabMatch) {
          const k = tabMatch[1].trim().toLowerCase();
          const v = tabMatch[2].trim();
          if (k.includes('id del mensaje') || k.includes('message id')) {
            reconstructed.push(`Message-ID: ${v}`);
          } else if (k === 'de' || k === 'from' || k.startsWith('de ') || k.startsWith('from ')) {
            reconstructed.push(`From: ${v}`);
          } else if (k === 'para' || k === 'to' || k.startsWith('para ') || k.startsWith('to ')) {
            reconstructed.push(`To: ${v}`);
          } else if (k === 'asunto' || k === 'subject' || k.startsWith('asunto ') || k.startsWith('subject ')) {
            reconstructed.push(`Subject: ${v}`);
          } else if (['creado', 'created', 'fecha', 'date'].some(x => k.includes(x))) {
            reconstructed.push(`Date: ${v}`);
          } else if (k.includes('spf')) {
            const ipM = v.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
            if (ipM) ipVal = ipM[0];
            spfVal = v.toLowerCase().includes('pass') ? 'pass' : (v.toLowerCase().includes('fail') ? 'fail' : 'neutral');
          } else if (k.includes('dkim')) {
            dkimVal = v.toLowerCase().includes('pass') ? 'pass' : 'fail';
          } else if (k.includes('dmarc')) {
            dmarcVal = v.toLowerCase().includes('pass') ? 'pass' : 'fail';
          }
        }
      }
      if (ipVal) {
        reconstructed.push(`Received: from mail.google.com ([${ipVal}]) by mx.google.com with ESMTPS;`);
        reconstructed.push(`Received-SPF: ${spfVal} client-ip=${ipVal};`);
      }
      reconstructed.push(`Authentication-Results: mx.google.com; spf=${spfVal} (client-ip=${ipVal || '209.85.220.41'}); dkim=${dkimVal}; dmarc=${dmarcVal}`);
      reconstructed.push('');
      reconstructed.push('(Contenido extraído del resumen de cabeceras de Gmail)');
      return reconstructed.join('\r\n');
    }

    // 3. Localized header aliases (Spanish web UI)
    const lines = text.split(/\r?\n/);
    const norm = [];
    let inHdr = true;
    for (let line of lines) {
      if (inHdr && !line.trim()) {
        inHdr = false;
      }
      if (inHdr) {
        line = line.replace(/^(?:De|From)\s*:\s*/i, 'From: ');
        line = line.replace(/^(?:Para|To)\s*:\s*/i, 'To: ');
        line = line.replace(/^(?:Asunto|Subject)\s*:\s*/i, 'Subject: ');
        line = line.replace(/^(?:Fecha|Date)\s*:\s*/i, 'Date: ');
        line = line.replace(/^(?:Responder a|Reply-To)\s*:\s*/i, 'Reply-To: ');
      }
      norm.push(line);
    }
    return norm.join('\r\n');
  }

  /**
   * Parse an EML buffer or string into structured email data
   * @param {Buffer|string} input 
   * @returns {Object} Structured email object
   */
  static parse(input) {
    const rawString = Buffer.isBuffer(input) ? input.toString('utf-8') : input;
    const normalizedString = this.normalizeRawEmail(rawString);
    
    // Split header section and body section (double CRLF or double LF)
    const splitMatch = normalizedString.match(/\r?\n\r?\n/);
    if (!splitMatch) {
      // Entire message might just be headers
      const headers = this.parseRawHeaders(normalizedString);
      return {
        headers,
        rawHeadersText: normalizedString,
        subject: this.decodeWord(headers['subject']?.[0] || ''),
        from: this.parseAddress(headers['from']?.[0] || ''),
        to: this.parseAddressList(headers['to']?.[0] || ''),
        cc: this.parseAddressList(headers['cc']?.[0] || ''),
        bcc: this.parseAddressList(headers['bcc']?.[0] || ''),
        date: headers['date']?.[0] || '',
        messageId: headers['message-id']?.[0] || '',
        replyTo: this.parseAddress(headers['reply-to']?.[0] || ''),
        returnPath: headers['return-path']?.[0] || '',
        textBody: '',
        htmlBody: '',
        attachments: [],
        size: Buffer.byteLength(normalizedString)
      };
    }

    const headerText = normalizedString.slice(0, splitMatch.index);
    const bodyText = normalizedString.slice(splitMatch.index + splitMatch[0].length);
    const headers = this.parseRawHeaders(headerText);

    const contentTypeHeader = headers['content-type']?.[0] || 'text/plain; charset=utf-8';
    const contentTransferEncoding = headers['content-transfer-encoding']?.[0] || '7bit';

    const parsedBody = this.parseBodyStructure(bodyText, contentTypeHeader, contentTransferEncoding);

    return {
      headers,
      rawHeadersText: headerText,
      subject: this.decodeWord(headers['subject']?.[0] || '(Sin asunto)'),
      from: this.parseAddress(headers['from']?.[0] || ''),
      to: this.parseAddressList(headers['to']?.[0] || ''),
      cc: this.parseAddressList(headers['cc']?.[0] || ''),
      bcc: this.parseAddressList(headers['bcc']?.[0] || ''),
      date: headers['date']?.[0] || '',
      messageId: headers['message-id']?.[0] || '',
      replyTo: this.parseAddress(headers['reply-to']?.[0] || ''),
      returnPath: headers['return-path']?.[0] || '',
      textBody: parsedBody.textBody,
      htmlBody: parsedBody.htmlBody,
      attachments: parsedBody.attachments,
      size: Buffer.byteLength(rawString)
    };
  }

  /**
   * Parse raw header text into an object with array of values per key
   * Unfolds multiline headers per RFC 5322 §2.2.3
   */
  static parseRawHeaders(headerText) {
    const headers = {};
    const lines = headerText.split(/\r?\n/);
    let currentKey = null;
    let currentValue = '';

    for (const line of lines) {
      if (/^[ \t]/.test(line)) {
        // Continuation line
        if (currentKey) {
          currentValue += ' ' + line.trim();
        }
      } else {
        if (currentKey) {
          const lKey = currentKey.toLowerCase();
          if (!headers[lKey]) headers[lKey] = [];
          headers[lKey].push(currentValue);
        }
        const colonIdx = line.indexOf(':');
        if (colonIdx > 0) {
          currentKey = line.slice(0, colonIdx).trim();
          currentValue = line.slice(colonIdx + 1).trim();
        } else {
          currentKey = null;
          currentValue = '';
        }
      }
    }

    if (currentKey) {
      const lKey = currentKey.toLowerCase();
      if (!headers[lKey]) headers[lKey] = [];
      headers[lKey].push(currentValue);
    }

    return headers;
  }

  /**
   * Parse Content-Type header into type and parameter key-values
   */
  static parseContentType(headerVal) {
    if (!headerVal) return { mimeType: 'text/plain', params: {} };
    const parts = headerVal.split(';');
    const mimeType = parts[0].trim().toLowerCase();
    const params = {};
    for (let i = 1; i < parts.length; i++) {
      const p = parts[i].trim();
      const eqIdx = p.indexOf('=');
      if (eqIdx > 0) {
        const k = p.slice(0, eqIdx).trim().toLowerCase();
        let v = p.slice(eqIdx + 1).trim();
        if (v.startsWith('"') && v.endsWith('"')) {
          v = v.slice(1, -1);
        }
        params[k] = v;
      }
    }
    return { mimeType, params };
  }

  /**
   * Parse body structure handling multipart recursively
   */
  static parseBodyStructure(bodyRaw, contentTypeHeader, defaultEncoding) {
    const { mimeType, params } = this.parseContentType(contentTypeHeader);
    const result = {
      textBody: '',
      htmlBody: '',
      attachments: []
    };

    if (mimeType.startsWith('multipart/') && params.boundary) {
      const boundary = params.boundary;
      const delimiter = '--' + boundary;
      const closeDelimiter = '--' + boundary + '--';
      
      const parts = bodyRaw.split(delimiter);
      for (let i = 1; i < parts.length; i++) {
        let part = parts[i];
        if (part.trim() === '--' || part.startsWith('--')) continue; // closing delimiter

        // Remove leading CRLF
        part = part.replace(/^(\r?\n)/, '');
        
        const splitMatch = part.match(/\r?\n\r?\n/);
        if (!splitMatch) continue;

        const partHeadersText = part.slice(0, splitMatch.index);
        const partBodyText = part.slice(splitMatch.index + splitMatch[0].length);
        const partHeaders = this.parseRawHeaders(partHeadersText);

        const partContentType = partHeaders['content-type']?.[0] || 'text/plain';
        const partEncoding = partHeaders['content-transfer-encoding']?.[0] || '7bit';
        const partDisposition = partHeaders['content-disposition']?.[0] || '';

        const parsedSub = this.parseBodyStructure(partBodyText, partContentType, partEncoding);
        
        // Check if this part is an attachment
        const dispParsed = this.parseContentType(partDisposition);
        const ctParsed = this.parseContentType(partContentType);
        const filename = dispParsed.params.filename || ctParsed.params.name || null;

        if (dispParsed.mimeType === 'attachment' || filename) {
          const decodedBuffer = this.decodeContentToBuffer(partBodyText, partEncoding);
          const safeName = this.decodeWord(filename || 'adjunto_desconocido');
          result.attachments.push({
            filename: safeName,
            contentType: ctParsed.mimeType || 'application/octet-stream',
            size: decodedBuffer.length,
            md5: crypto.createHash('md5').update(decodedBuffer).digest('hex'),
            sha256: crypto.createHash('sha256').update(decodedBuffer).digest('hex'),
            dataBase64: decodedBuffer.toString('base64'),
            isSuspicious: this.isSuspiciousExtension(safeName)
          });
        } else {
          if (parsedSub.textBody && !result.textBody) result.textBody = parsedSub.textBody;
          if (parsedSub.htmlBody && !result.htmlBody) result.htmlBody = parsedSub.htmlBody;
          if (parsedSub.attachments.length > 0) {
            result.attachments.push(...parsedSub.attachments);
          }
        }
      }
    } else {
      // Single part
      const decodedBuffer = this.decodeContentToBuffer(bodyRaw, defaultEncoding);
      const text = this.decodeBufferToText(decodedBuffer, params.charset || 'utf-8');

      if (mimeType === 'text/html') {
        result.htmlBody = text;
      } else if (mimeType === 'text/plain') {
        result.textBody = text;
      } else {
        // Attachment in single body
        const filename = params.name || 'documento';
        result.attachments.push({
          filename: this.decodeWord(filename),
          contentType: mimeType,
          size: decodedBuffer.length,
          md5: crypto.createHash('md5').update(decodedBuffer).digest('hex'),
          sha256: crypto.createHash('sha256').update(decodedBuffer).digest('hex'),
          dataBase64: decodedBuffer.toString('base64'),
          isSuspicious: this.isSuspiciousExtension(filename)
        });
      }
    }

    return result;
  }

  /**
   * Decode transfer encodings into raw Buffer
   */
  static decodeContentToBuffer(content, encoding) {
    const enc = (encoding || '').toLowerCase().trim();
    if (enc === 'base64') {
      const cleanB64 = content.replace(/[^A-Za-z0-9+/=]/g, '');
      return Buffer.from(cleanB64, 'base64');
    } else if (enc === 'quoted-printable') {
      return this.decodeQuotedPrintable(content);
    } else {
      return Buffer.from(content, 'utf-8');
    }
  }

  /**
   * Decodes Quoted-Printable content to Buffer
   */
  static decodeQuotedPrintable(str) {
    // Soft line breaks: =\r\n or =\n
    const cleaned = str.replace(/=\r?\n/g, '');
    const bytes = [];
    for (let i = 0; i < cleaned.length; i++) {
      if (cleaned[i] === '=' && i + 2 < cleaned.length) {
        const hex = cleaned.slice(i + 1, i + 3);
        if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
          bytes.push(parseInt(hex, 16));
          i += 2;
          continue;
        }
      }
      bytes.push(cleaned.charCodeAt(i) & 0xff);
    }
    return Buffer.from(bytes);
  }

  /**
   * Decode buffer to string with charset fallback
   */
  static decodeBufferToText(buf, charset) {
    const cs = (charset || 'utf-8').toLowerCase().replace(/[^a-z0-9-]/g, '');
    try {
      if (cs.includes('iso-8859-1') || cs.includes('latin1')) {
        return buf.toString('latin1');
      } else if (cs.includes('windows-1252')) {
        return buf.toString('latin1'); // Node maps reasonably
      } else {
        return buf.toString('utf-8');
      }
    } catch {
      return buf.toString('utf-8');
    }
  }

  /**
   * Decodes RFC 2047 encoded words: =?charset?Q|B?encoded_text?=
   */
  static decodeWord(word) {
    if (!word || typeof word !== 'string') return '';
    return word.replace(/=\?([^?]+)\?([QBqb])\?([^?]*)\?=/g, (match, charset, encoding, text) => {
      try {
        const isB64 = encoding.toUpperCase() === 'B';
        let buf;
        if (isB64) {
          buf = Buffer.from(text, 'base64');
        } else {
          // Quoted-printable in RFC 2047: underscores represent spaces
          const qp = text.replace(/_/g, '=20');
          buf = this.decodeQuotedPrintable(qp);
        }
        return this.decodeBufferToText(buf, charset);
      } catch {
        return text;
      }
    });
  }

  /**
   * Parse email address header e.g. "John Doe <john@example.com>"
   */
  static parseAddress(raw) {
    if (!raw) return { name: '', address: '', domain: '', full: '' };
    const decoded = this.decodeWord(raw).trim();
    const angleMatch = decoded.match(/^(.*?)\s*<([^>]+)>/);
    if (angleMatch) {
      let name = angleMatch[1].trim().replace(/^["']|["']$/g, '');
      let address = angleMatch[2].trim().toLowerCase();
      let domain = address.includes('@') ? address.split('@')[1] : '';
      return { name, address, domain, full: decoded };
    }
    // Direct address
    const cleanAddr = decoded.trim().replace(/^["'<>]|["'<>]$/g, '').toLowerCase();
    const domain = cleanAddr.includes('@') ? cleanAddr.split('@')[1] : '';
    return { name: cleanAddr, address: cleanAddr, domain, full: decoded };
  }

  /**
   * Parse list of addresses separated by commas
   */
  static parseAddressList(raw) {
    if (!raw) return [];
    const parts = raw.split(/,(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)/);
    return parts.map(p => this.parseAddress(p)).filter(a => a.address);
  }

  /**
   * Security check for dangerous attachment extensions
   */
  static isSuspiciousExtension(filename) {
    if (!filename) return false;
    const lower = filename.toLowerCase();
    const dangerousExts = [
      '.exe', '.dll', '.bat', '.cmd', '.scr', '.vbs', '.vbe', '.js', '.jse',
      '.wsf', '.wsh', '.hta', '.ps1', '.iso', '.img', '.docm', '.xlsm', '.pptm',
      '.pif', '.cpl', '.jar', '.com', '.reg', '.lnk'
    ];
    return dangerousExts.some(ext => lower.endsWith(ext));
  }
}

module.exports = MimeParser;

