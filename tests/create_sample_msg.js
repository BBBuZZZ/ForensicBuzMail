/**
 * Utility script to generate a valid Outlook .msg (CFBF Compound File) sample
 * for testing and demonstration purposes.
 */
const fs = require('node:fs');
const path = require('node:path');

function createSampleMsg(outputPath) {
  const SECTOR_SIZE = 512;
  const MINI_SECTOR_SIZE = 64;

  // Streams to include in the MSG file
  const transportHeaders = [
    'Received: from relay.empresa-aliada.es (relay.empresa-aliada.es [195.55.201.40])',
    '        by mx01.mycompany.org with ESMTPS id 5A6B7C8D',
    '        for <director@mycompany.org>; Mon, 12 Oct 2026 11:20:05 +0200',
    'Authentication-Results: mx01.mycompany.org;',
    '       dkim=pass header.i=@empresa-aliada.es header.s=corp2026;',
    '       spf=pass (empresa-aliada.es: 195.55.201.40 is permitted) smtp.mailfrom=facturacion@empresa-aliada.es;',
    '       dmarc=pass (p=quarantine) header.from=empresa-aliada.es',
    'Received-SPF: pass (empresa-aliada.es: 195.55.201.40 is permitted) client-ip=195.55.201.40; envelope-from=facturacion@empresa-aliada.es;',
    'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=empresa-aliada.es; s=corp2026;',
    '       h=from:to:subject:date:message-id;',
    '       bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=;',
    '       b=C8yH7...==',
    'From: "Contabilidad Global" <facturacion@empresa-aliada.es>',
    'To: director@mycompany.org',
    'Subject: Factura de Servicios Profesionales #48291',
    'Date: Mon, 12 Oct 2026 11:19:42 +0200',
    'Message-ID: <msg.20261012.48291@empresa-aliada.es>',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8'
  ].join('\r\n');

  const streams = [
    {
      name: '__substg1.0_007D001F', // PR_TRANSPORT_MESSAGE_HEADERS
      data: Buffer.from(transportHeaders, 'utf16le')
    },
    {
      name: '__substg1.0_0037001F', // PR_SUBJECT
      data: Buffer.from('Factura de Servicios Profesionales #48291', 'utf16le')
    },
    {
      name: '__substg1.0_0C1F001F', // PR_SENDER_NAME
      data: Buffer.from('Contabilidad Global', 'utf16le')
    },
    {
      name: '__substg1.0_0C1E001F', // PR_SENDER_EMAIL_ADDRESS
      data: Buffer.from('facturacion@empresa-aliada.es', 'utf16le')
    },
    {
      name: '__substg1.0_0E04001F', // PR_DISPLAY_TO
      data: Buffer.from('director@mycompany.org', 'utf16le')
    },
    {
      name: '__substg1.0_1000001F', // PR_BODY
      data: Buffer.from('Estimado cliente:\n\nAdjuntamos la factura correspondiente al cierre de operaciones de septiembre.\nQuedamos a su disposición para cualquier aclaración contable.\n\nAtentamente,\nDepartamento de Facturación\nContabilidad Global S.L.', 'utf16le')
    },
    {
      name: '__substg1.0_3707001F', // PR_ATTACH_FILENAME
      data: Buffer.from('Factura_48291.pdf', 'utf16le')
    },
    {
      name: '__substg1.0_370E001F', // PR_ATTACH_MIME_TAG
      data: Buffer.from('application/pdf', 'utf16le')
    },
    {
      name: '__substg1.0_37010102', // PR_ATTACH_DATA_BIN
      data: Buffer.from('%PDF-1.4\n%Demo PDF Invoice content for forensic testing.\n%%EOF', 'utf-8')
    }
  ];

  // Concatenate streams into sectors
  const sectorList = [];
  const dirEntries = [];

  // Root entry (Entry 0)
  const rootNameBuf = Buffer.from('Root Entry\0', 'utf16le');
  const rootEntry = Buffer.alloc(128);
  rootNameBuf.copy(rootEntry, 0);
  rootEntry.writeUInt16LE(rootNameBuf.length, 64);
  rootEntry.writeUInt8(5, 66); // Root Storage
  rootEntry.writeInt32LE(-1, 68); // Left sibling
  rootEntry.writeInt32LE(-1, 72); // Right sibling
  rootEntry.writeInt32LE(1, 76);  // Child (first stream)
  rootEntry.writeUInt32LE(0xFFFFFFFE, 116); // Starting sector
  rootEntry.writeBigUInt64LE(0n, 120); // Stream size
  dirEntries.push(rootEntry);

  // Allocate sectors for each stream directly
  const fatTable = [];

  streams.forEach((st, idx) => {
    const streamLen = st.data.length;
    const numSectorsNeeded = Math.ceil(streamLen / SECTOR_SIZE) || 1;
    const startSec = sectorList.length;

    for (let s = 0; s < numSectorsNeeded; s++) {
      const slice = st.data.subarray(s * SECTOR_SIZE, (s + 1) * SECTOR_SIZE);
      const secBuf = Buffer.alloc(SECTOR_SIZE, 0);
      slice.copy(secBuf, 0);
      sectorList.push(secBuf);

      if (s < numSectorsNeeded - 1) {
        fatTable.push(startSec + s + 1);
      } else {
        fatTable.push(0xFFFFFFFE); // End of chain
      }
    }

    // Build directory entry (128 bytes)
    const nameBuf = Buffer.from(st.name + '\0', 'utf16le');
    const dEntry = Buffer.alloc(128);
    nameBuf.copy(dEntry, 0);
    dEntry.writeUInt16LE(nameBuf.length, 64);
    dEntry.writeUInt8(2, 66); // Stream
    // Simple BST chaining
    dEntry.writeInt32LE(-1, 68);
    dEntry.writeInt32LE(idx < streams.length - 1 ? idx + 2 : -1, 72);
    dEntry.writeInt32LE(-1, 76);
    dEntry.writeUInt32LE(startSec, 116);
    dEntry.writeBigUInt64LE(BigInt(streamLen), 120);
    dirEntries.push(dEntry);
  });

  // Pack directory entries into directory sectors
  const dirSectorStart = sectorList.length;
  const dirBuffer = Buffer.concat(dirEntries);
  const numDirSectors = Math.ceil(dirBuffer.length / SECTOR_SIZE) || 1;

  for (let s = 0; s < numDirSectors; s++) {
    const slice = dirBuffer.subarray(s * SECTOR_SIZE, (s + 1) * SECTOR_SIZE);
    const secBuf = Buffer.alloc(SECTOR_SIZE, 0);
    slice.copy(secBuf, 0);
    sectorList.push(secBuf);

    if (s < numDirSectors - 1) {
      fatTable.push(dirSectorStart + s + 1);
    } else {
      fatTable.push(0xFFFFFFFE);
    }
  }

  // Pack FAT table into FAT sectors
  const fatSectorStart = sectorList.length;
  // Mark FAT sector itself in FAT
  fatTable.push(0xFFFFFFFD); // FAT sector marker

  const fatBuffer = Buffer.alloc(SECTOR_SIZE, 0xFF);
  for (let i = 0; i < fatTable.length; i++) {
    fatBuffer.writeUInt32LE(fatTable[i], i * 4);
  }
  sectorList.push(fatBuffer);

  // Build CFBF Header (512 bytes)
  const header = Buffer.alloc(SECTOR_SIZE, 0);
  // Signature
  Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]).copy(header, 0);
  header.writeUInt16LE(0xFFFE, 28); // Byte order
  header.writeUInt16LE(9, 30);      // Sector shift = 9 (512 bytes)
  header.writeUInt16LE(6, 32);      // Mini sector shift = 6 (64 bytes)
  header.writeUInt32LE(1, 44);      // Number of FAT sectors
  header.writeUInt32LE(dirSectorStart, 48); // First directory sector
  header.writeUInt32LE(4096, 56);   // Mini stream cutoff
  header.writeUInt32LE(0xFFFFFFFE, 60); // First Mini-FAT sector
  header.writeUInt32LE(0, 64);      // Num Mini-FAT sectors
  header.writeUInt32LE(0xFFFFFFFE, 68); // First DIFAT sector
  header.writeUInt32LE(0, 72);      // Num DIFAT sectors
  header.writeUInt32LE(fatSectorStart, 76); // DIFAT[0] points to fatSectorStart

  // Fill remaining DIFAT entries with 0xFFFFFFFF
  for (let i = 1; i < 109; i++) {
    header.writeUInt32LE(0xFFFFFFFF, 76 + i * 4);
  }

  const finalFileBuffer = Buffer.concat([header, ...sectorList]);
  fs.writeFileSync(outputPath, finalFileBuffer);
  console.log(`[MSG Builder] Archivo .msg generado con éxito: ${outputPath} (${finalFileBuffer.length} bytes)`);
}

module.exports = { createSampleMsg };

if (require.main === module) {
  const target = path.join(__dirname, '..', 'samples', 'invoice_sample.msg');
  createSampleMsg(target);
}

