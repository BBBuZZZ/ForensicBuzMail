/**
 * Outlook .msg (MS-OXMSG / CFBF Compound File Binary Format) Parser
 * Pure Node.js zero-dependency implementation.
 */
const crypto = require('node:crypto');
const MimeParser = require('./mime_parser');

const CFBF_SIGNATURE = Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);

class MsgParser {
  /**
   * Check if buffer is a valid CFBF / MSG file
   * @param {Buffer} buffer 
   * @returns {boolean}
   */
  static isMsgFile(buffer) {
    if (!Buffer.isBuffer(buffer) || buffer.length < 512) return false;
    return buffer.subarray(0, 8).equals(CFBF_SIGNATURE);
  }

  /**
   * Parse a .msg file buffer
   * @param {Buffer} buffer 
   * @returns {Object} Structured email object compatible with MimeParser output
   */
  static parse(buffer) {
    if (!this.isMsgFile(buffer)) {
      throw new Error('El archivo no tiene la firma válida de un archivo Outlook .msg (CFBF OLE2).');
    }

    const cfb = this.readCFBF(buffer);
    const properties = this.extractMsgProperties(cfb);

    let rawHeadersText = properties.transportHeaders || '';
    let emailData;

    if (rawHeadersText && rawHeadersText.trim().length > 0) {
      // We have transport headers, parse them with MimeParser for full fidelity
      emailData = MimeParser.parse(rawHeadersText + "\r\n\r\n" + (properties.body || ''));
    } else {
      // Fallback: construct headers from MAPI properties
      const constructedHeaders = {};
      if (properties.subject) constructedHeaders['subject'] = [properties.subject];
      if (properties.sender) constructedHeaders['from'] = [properties.sender];
      if (properties.displayTo) constructedHeaders['to'] = [properties.displayTo];
      if (properties.displayCc) constructedHeaders['cc'] = [properties.displayCc];
      if (properties.clientSubmitTime) constructedHeaders['date'] = [properties.clientSubmitTime];
      if (properties.messageId) constructedHeaders['message-id'] = [properties.messageId];

      emailData = {
        headers: constructedHeaders,
        rawHeadersText: Object.entries(constructedHeaders).map(([k, v]) => `${k}: ${v[0]}`).join('\r\n'),
        subject: properties.subject || '(Sin asunto)',
        from: MimeParser.parseAddress(properties.sender || ''),
        to: MimeParser.parseAddressList(properties.displayTo || ''),
        cc: MimeParser.parseAddressList(properties.displayCc || ''),
        bcc: MimeParser.parseAddressList(properties.displayBcc || ''),
        date: properties.clientSubmitTime || '',
        messageId: properties.messageId || '',
        replyTo: MimeParser.parseAddress(properties.replyTo || ''),
        returnPath: properties.returnPath || '',
        textBody: properties.body || '',
        htmlBody: properties.htmlBody || '',
        attachments: [],
        size: buffer.length
      };
    }

    // Overlay extracted HTML or plain body if MimeParser did not have it
    if (properties.body && !emailData.textBody) {
      emailData.textBody = properties.body;
    }
    if (properties.htmlBody && !emailData.htmlBody) {
      emailData.htmlBody = properties.htmlBody;
    }

    // Attachments from MSG structure
    if (properties.attachments && properties.attachments.length > 0) {
      for (const att of properties.attachments) {
        if (!emailData.attachments.some(a => a.filename === att.filename && a.size === att.size)) {
          emailData.attachments.push(att);
        }
      }
    }

    return emailData;
  }

  /**
   * Low-level CFBF structure parser
   */
  static readCFBF(buf) {
    const sectorShift = buf.readUInt16LE(30);
    const sectorSize = 1 << sectorShift; // usually 512
    const miniSectorShift = buf.readUInt16LE(32);
    const miniSectorSize = 1 << miniSectorShift; // usually 64
    const numFatSectors = buf.readUInt32LE(44);
    const firstDirSector = buf.readUInt32LE(48);
    const miniStreamCutoff = buf.readUInt32LE(56); // usually 4096
    const firstMiniFatSector = buf.readUInt32LE(60);
    const numMiniFatSectors = buf.readUInt32LE(64);
    const firstDifatSector = buf.readUInt32LE(68);
    const numDifatSectors = buf.readUInt32LE(72);

    // Read DIFAT (first 109 entries are in the header at offset 76)
    const fatSectorIndices = [];
    for (let i = 0; i < 109 && i < numFatSectors; i++) {
      const sec = buf.readUInt32LE(76 + i * 4);
      if (sec <= 0xFFFFFFFA) {
        fatSectorIndices.push(sec);
      }
    }

    // Extra DIFAT sectors if file is large (> 6.8MB)
    if (numDifatSectors > 0 && firstDifatSector <= 0xFFFFFFFA) {
      let curDifat = firstDifatSector;
      const entriesPerSector = (sectorSize / 4) - 1;
      while (curDifat <= 0xFFFFFFFA) {
        const offset = (curDifat + 1) * sectorSize;
        if (offset + sectorSize > buf.length) break;
        for (let i = 0; i < entriesPerSector; i++) {
          const sec = buf.readUInt32LE(offset + i * 4);
          if (sec <= 0xFFFFFFFA) fatSectorIndices.push(sec);
        }
        curDifat = buf.readUInt32LE(offset + entriesPerSector * 4);
      }
    }

    // Read full FAT table
    const fat = [];
    for (const fatSec of fatSectorIndices) {
      const offset = (fatSec + 1) * sectorSize;
      if (offset + sectorSize > buf.length) break;
      const count = sectorSize / 4;
      for (let i = 0; i < count; i++) {
        fat.push(buf.readUInt32LE(offset + i * 4));
      }
    }

    // Read Mini-FAT
    const miniFat = [];
    if (numMiniFatSectors > 0 && firstMiniFatSector <= 0xFFFFFFFA) {
      let curSec = firstMiniFatSector;
      while (curSec <= 0xFFFFFFFA) {
        const offset = (curSec + 1) * sectorSize;
        if (offset + sectorSize > buf.length) break;
        const count = sectorSize / 4;
        for (let i = 0; i < count; i++) {
          miniFat.push(buf.readUInt32LE(offset + i * 4));
        }
        curSec = fat[curSec];
      }
    }

    // Helper to read a sector chain from FAT
    const readChain = (startSector) => {
      const chunks = [];
      let cur = startSector;
      let guard = 0;
      while (cur <= 0xFFFFFFFA && guard++ < 200000) {
        const offset = (cur + 1) * sectorSize;
        if (offset + sectorSize <= buf.length) {
          chunks.push(buf.subarray(offset, offset + sectorSize));
        }
        cur = fat[cur];
      }
      return Buffer.concat(chunks);
    };

    // Read directory entries (128 bytes each)
    const dirStream = readChain(firstDirSector);
    const dirEntries = [];
    const numEntries = Math.floor(dirStream.length / 128);

    for (let i = 0; i < numEntries; i++) {
      const dOffset = i * 128;
      const entryBuf = dirStream.subarray(dOffset, dOffset + 128);
      const nameLen = entryBuf.readUInt16LE(64);
      if (nameLen === 0) continue;

      let name = '';
      try {
        // Name is UTF-16LE, excluding terminating null
        const charLen = Math.max(0, Math.floor(nameLen / 2) - 1);
        name = entryBuf.subarray(0, charLen * 2).toString('utf16le');
      } catch {
        name = `Entry_${i}`;
      }

      const type = entryBuf.readUInt8(66); // 1 = Storage, 2 = Stream, 5 = Root
      const startSector = entryBuf.readUInt32LE(116);
      const streamSize = Number(entryBuf.readBigUInt64LE(120));

      dirEntries.push({
        index: i,
        name,
        type,
        startSector,
        streamSize
      });
    }

    // The root entry contains the Mini Stream container
    const rootEntry = dirEntries[0];
    let miniStreamData = Buffer.alloc(0);
    if (rootEntry && rootEntry.startSector <= 0xFFFFFFFA) {
      miniStreamData = readChain(rootEntry.startSector);
      if (rootEntry.streamSize < miniStreamData.length) {
        miniStreamData = miniStreamData.subarray(0, rootEntry.streamSize);
      }
    }

    // Helper to read stream data for an entry
    const readEntryData = (entry) => {
      if (!entry || entry.streamSize === 0) return Buffer.alloc(0);

      if (entry.streamSize < miniStreamCutoff && miniStreamData.length > 0) {
        // Read from Mini FAT
        const chunks = [];
        let cur = entry.startSector;
        let guard = 0;
        while (cur <= 0xFFFFFFFA && guard++ < 200000) {
          const offset = cur * miniSectorSize;
          if (offset + miniSectorSize <= miniStreamData.length) {
            chunks.push(miniStreamData.subarray(offset, offset + miniSectorSize));
          }
          cur = miniFat[cur];
        }
        const full = Buffer.concat(chunks);
        return full.subarray(0, Math.min(entry.streamSize, full.length));
      } else {
        // Regular stream
        const full = readChain(entry.startSector);
        return full.subarray(0, Math.min(entry.streamSize, full.length));
      }
    };

    return {
      entries: dirEntries,
      readEntryData
    };
  }

  /**
   * Extract MAPI properties and transport headers from CFBF entries
   */
  static extractMsgProperties(cfb) {
    const props = {
      subject: '',
      sender: '',
      displayTo: '',
      displayCc: '',
      displayBcc: '',
      body: '',
      htmlBody: '',
      transportHeaders: '',
      clientSubmitTime: '',
      messageId: '',
      replyTo: '',
      returnPath: '',
      attachments: []
    };

    // Group entries by storage path (root vs attachments)
    const attachmentStreams = {};

    for (const entry of cfb.entries) {
      if (entry.type !== 2) continue; // Only Streams

      const name = entry.name;

      // Check if it belongs to an attachment e.g. __attach_version1.0_#00000000
      // In CFBF directory tree, stream names might have storage parents or direct prefix
      if (name.startsWith('__substg1.0_')) {
        const tag = name.slice(12, 16).toUpperCase();
        const type = name.slice(16, 20).toUpperCase();

        const data = cfb.readEntryData(entry);

        if (tag === '007D') {
          // PR_TRANSPORT_MESSAGE_HEADERS
          props.transportHeaders = this.decodeString(data, type);
        } else if (tag === '0037') {
          // PR_SUBJECT
          props.subject = this.decodeString(data, type);
        } else if (tag === '0C1F' || tag === '0C1E') {
          // PR_SENDER_NAME / PR_SENDER_EMAIL_ADDRESS
          const val = this.decodeString(data, type);
          if (val && (!props.sender || !props.sender.includes('@'))) {
            props.sender = val;
          }
        } else if (tag === '0E04') {
          // PR_DISPLAY_TO
          props.displayTo = this.decodeString(data, type);
        } else if (tag === '0E03') {
          // PR_DISPLAY_CC
          props.displayCc = this.decodeString(data, type);
        } else if (tag === '0E02') {
          // PR_DISPLAY_BCC
          props.displayBcc = this.decodeString(data, type);
        } else if (tag === '1000') {
          // PR_BODY (Plain text)
          props.body = this.decodeString(data, type);
        } else if (tag === '1013') {
          // PR_HTML
          props.htmlBody = data.toString('utf-8');
        } else if (tag === '1035') {
          // PR_INTERNET_MESSAGE_ID
          props.messageId = this.decodeString(data, type);
        } else if (tag === '1009') {
          // PR_RTF_COMPRESSED (if needed, but usually html or text exists)
        }
      }
    }

    // Extract attachments by scanning directory entries
    // Attachment storages are usually named "__attach_version1.0_#XXXXXXXX"
    for (let i = 0; i < cfb.entries.length; i++) {
      const e = cfb.entries[i];
      if (e.name.startsWith('__attach_version1.0_')) {
        // Collect attachment streams
        const attId = e.name;
        if (!attachmentStreams[attId]) attachmentStreams[attId] = {};
      }
    }

    // In a flat listing, attachment streams have parent indices or follow the attachment storage
    for (let i = 0; i < cfb.entries.length; i++) {
      const e = cfb.entries[i];
      if (e.name.startsWith('__substg1.0_')) {
        const tag = e.name.slice(12, 16).toUpperCase();
        const type = e.name.slice(16, 20).toUpperCase();
        
        // Attachment tags
        if (tag === '3701') { // PR_ATTACH_DATA_BIN
          const data = cfb.readEntryData(e);
          if (data && data.length > 0) {
            // Find filename around this entry or in previous
            const attObj = {
              filename: 'adjunto_msg.dat',
              contentType: 'application/octet-stream',
              size: data.length,
              md5: crypto.createHash('md5').update(data).digest('hex'),
              sha256: crypto.createHash('sha256').update(data).digest('hex'),
              dataBase64: data.toString('base64'),
              isSuspicious: false
            };

            // Look ahead/behind for name
            for (let j = Math.max(0, i - 10); j < Math.min(cfb.entries.length, i + 10); j++) {
              const other = cfb.entries[j];
              const oTag = other.name.slice(12, 16).toUpperCase();
              const oType = other.name.slice(16, 20).toUpperCase();
              if (oTag === '3707' || oTag === '3704') { // Filename or Long Filename
                const nameStr = this.decodeString(cfb.readEntryData(other), oType);
                if (nameStr) attObj.filename = nameStr.replace(/[\0\r\n]/g, '').trim();
              }
              if (oTag === '370E') { // MIME tag
                const mime = this.decodeString(cfb.readEntryData(other), oType);
                if (mime) attObj.contentType = mime.replace(/[\0\r\n]/g, '').trim();
              }
            }

            attObj.isSuspicious = MimeParser.isSuspiciousExtension(attObj.filename);
            props.attachments.push(attObj);
          }
        }
      }
    }

    return props;
  }

  /**
   * Decode property buffer based on type (001F Unicode, 001E ANSI string, etc.)
   */
  static decodeString(data, type) {
    if (!data || data.length === 0) return '';
    try {
      if (type === '001F') {
        // UTF-16LE
        return data.toString('utf16le').replace(/\0+$/, '');
      } else if (type === '001E') {
        // ANSI / Latin1
        return data.toString('latin1').replace(/\0+$/, '');
      } else {
        // Fallback string
        return data.toString('utf-8').replace(/\0+$/, '');
      }
    } catch {
      return '';
    }
  }
}

module.exports = MsgParser;

