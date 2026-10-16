/**
 * Email Forensics & Security Analyzer - Local Server
 * 100% Local, zero-dependency Node.js HTTP server and REST API.
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const MimeParser = require('./parsers/mime_parser');
const MsgParser = require('./parsers/msg_parser');
const HeaderAnalyzer = require('./parsers/header_analyzer');
const SpfAnalyzer = require('./security/spf_analyzer');
const DkimAnalyzer = require('./security/dkim_analyzer');
const DmarcAnalyzer = require('./security/dmarc_analyzer');
const RiskEngine = require('./security/risk_engine');
const IpGeolocator = require('./security/ip_geolocator');
const ForensicDatabase = require('./database');

const PORT = parseInt(process.env.PORT || '8080', 10);
const PUBLIC_DIR = path.join(__dirname, 'public');
const SAMPLES_DIR = path.join(__dirname, 'samples');

// Initialize database
const db = new ForensicDatabase(path.join(__dirname, 'data'));

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.eml': 'message/rfc822',
  '.msg': 'application/vnd.ms-outlook'
};

/**
 * Core analysis pipeline
 */
function runEmailAnalysis(fileBuffer, originalFilename = 'mensaje.eml') {
  const isMsg = MsgParser.isMsgFile(fileBuffer) || originalFilename.toLowerCase().endsWith('.msg');
  const fileType = isMsg ? 'msg' : 'eml';

  let email;
  if (isMsg) {
    email = MsgParser.parse(fileBuffer);
  } else {
    email = MimeParser.parse(fileBuffer);
  }

  // 1. SPF Analysis
  const spf = SpfAnalyzer.analyze(email.headers, email.from, email.returnPath);

  // 2. DKIM Analysis
  const dkim = DkimAnalyzer.analyze(email.headers, email.from);

  // 3. DMARC Analysis
  const dmarc = DmarcAnalyzer.analyze(email.headers, spf, dkim, email.from);

  // 4. Network Route & SMTP Hops
  const network = HeaderAnalyzer.analyzeNetworkRoute(email.headers);

  // 5. Risk Assessment Engine
  const risk = RiskEngine.evaluate(email, spf, dkim, dmarc, network);

  const analysisResult = {
    id: crypto.randomUUID(),
    filename: originalFilename,
    fileType,
    fileSize: fileBuffer.length,
    analyzedAt: new Date().toISOString(),
    email: {
      subject: email.subject,
      from: email.from,
      to: email.to,
      cc: email.cc,
      bcc: email.bcc,
      date: email.date,
      messageId: email.messageId,
      replyTo: email.replyTo,
      returnPath: email.returnPath,
      textBody: email.textBody,
      htmlBody: email.htmlBody,
      attachments: email.attachments,
      rawHeadersText: email.rawHeadersText
    },
    spf,
    dkim,
    dmarc,
    network,
    risk
  };

  // Persist to local database
  db.saveAnalysis(analysisResult);

  return analysisResult;
}

/**
 * Request Handler
 */
const server = http.createServer(async (req, res) => {
  // Security and CORS headers for local environment
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  // API ROUTING
  if (pathname.startsWith('/api/')) {
    try {
      // POST /api/analyze
      if (pathname === '/api/analyze' && req.method === 'POST') {
        const bodyBuf = await readRequestBodyBuffer(req);
        
        let fileBuffer;
        let originalFilename = 'archivo_analizado.eml';

        const contentType = req.headers['content-type'] || '';
        if (contentType.includes('application/json')) {
          const jsonBody = JSON.parse(bodyBuf.toString('utf-8'));
          if (jsonBody.base64) {
            fileBuffer = Buffer.from(jsonBody.base64, 'base64');
          } else if (jsonBody.rawText) {
            fileBuffer = Buffer.from(jsonBody.rawText, 'utf-8');
          } else {
            throw new Error('Cuerpo JSON no contiene datos de archivo (base64 o rawText).');
          }
          if (jsonBody.filename) originalFilename = jsonBody.filename;
        } else if (contentType.includes('multipart/form-data')) {
          const parsedMultipart = parseMultipartUpload(bodyBuf, contentType);
          if (!parsedMultipart.buffer) {
            throw new Error('No se encontró archivo en la petición multipart.');
          }
          fileBuffer = parsedMultipart.buffer;
          if (parsedMultipart.filename) originalFilename = parsedMultipart.filename;
        } else {
          // Direct octet-stream / raw text
          fileBuffer = bodyBuf;
          const nameHeader = req.headers['x-filename'];
          if (nameHeader) originalFilename = decodeURIComponent(nameHeader);
        }

        const result = runEmailAnalysis(fileBuffer, originalFilename);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: true, data: result }));
        return;
      }

      // GET /api/history
      if (pathname === '/api/history' && req.method === 'GET') {
        const limit = parseInt(parsedUrl.searchParams.get('limit') || '50', 10);
        const offset = parseInt(parsedUrl.searchParams.get('offset') || '0', 10);
        const query = parsedUrl.searchParams.get('q') || '';
        const history = db.getHistory(limit, offset, query);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: true, data: history }));
        return;
      }

      // GET /api/history/:id
      if (pathname.startsWith('/api/history/') && req.method === 'GET') {
        const id = pathname.slice('/api/history/'.length);
        const analysis = db.getAnalysisById(id);
        if (!analysis) {
          res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Análisis no encontrado' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: true, data: analysis }));
        return;
      }

      // DELETE /api/history/:id
      if (pathname.startsWith('/api/history/') && req.method === 'DELETE') {
        const id = pathname.slice('/api/history/'.length);
        db.deleteAnalysis(id);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: true, message: 'Registro eliminado' }));
        return;
      }

      // GET /api/stats
      if (pathname === '/api/stats' && req.method === 'GET') {
        const stats = db.getStats();
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: true, data: stats }));
        return;
      }

      // GET /api/samples
      if (pathname === '/api/samples' && req.method === 'GET') {
        const sampleFiles = [];
        if (fs.existsSync(SAMPLES_DIR)) {
          const files = fs.readdirSync(SAMPLES_DIR);
          for (const f of files) {
            const fullPath = path.join(SAMPLES_DIR, f);
            const stat = fs.statSync(fullPath);
            if (stat.isFile() && (f.endsWith('.eml') || f.endsWith('.msg'))) {
              sampleFiles.push({
                name: f,
                size: stat.size,
                type: f.endsWith('.msg') ? 'msg' : 'eml'
              });
            }
          }
        }
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: true, data: sampleFiles }));
        return;
      }

      // POST /api/samples/:name
      if (pathname.startsWith('/api/samples/') && req.method === 'POST') {
        const sampleName = decodeURIComponent(pathname.slice('/api/samples/'.length));
        const samplePath = path.join(SAMPLES_DIR, sampleName);
        if (!fs.existsSync(samplePath) || !fs.statSync(samplePath).isFile()) {
          res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Muestra no encontrada' }));
          return;
        }
        const fileBuf = fs.readFileSync(samplePath);
        const result = runEmailAnalysis(fileBuf, sampleName);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: true, data: result }));
        return;
      }

      // GET /api/geolocate?ip=...
      if (pathname === '/api/geolocate' && req.method === 'GET') {
        const ip = parsedUrl.searchParams.get('ip') || '';
        if (!ip) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: "Parámetro 'ip' requerido" }));
          return;
        }
        const geoData = await IpGeolocator.lookupOnline(ip);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: true, data: geoData }));
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Ruta de API desconocida' }));
      return;
    } catch (err) {
      console.error('[API Error]:', err);
      res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: err.message || 'Error interno del servidor' }));
      return;
    }
  }

  // STATIC FILE SERVING
  let safePath = pathname === '/' ? '/index.html' : pathname;
  // Prevent directory traversal
  safePath = path.normalize(safePath).replace(/^(\.\.[\/\\])+/, '');
  const filePath = path.join(PUBLIC_DIR, safePath);

  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    // Fallback to index.html for SPA if not found
    const indexPath = path.join(PUBLIC_DIR, 'index.html');
    if (fs.existsSync(indexPath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      fs.createReadStream(indexPath).pipe(res);
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('404 Not Found');
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': contentType });
  fs.createReadStream(filePath).pipe(res);
});

/**
 * Read request body buffer
 */
function readRequestBodyBuffer(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', err => reject(err));
  });
}

/**
 * Lightweight multipart form parser for file uploads
 */
function parseMultipartUpload(buffer, contentType) {
  const boundaryMatch = contentType.match(/boundary=([^\s;]+)/i);
  if (!boundaryMatch) return { buffer: null, filename: null };

  let boundary = boundaryMatch[1];
  if (boundary.startsWith('"') && boundary.endsWith('"')) {
    boundary = boundary.slice(1, -1);
  }

  const delimiter = Buffer.from('--' + boundary);
  let startIdx = buffer.indexOf(delimiter);
  if (startIdx === -1) return { buffer: null, filename: null };

  let filename = 'correo.eml';
  let fileData = null;

  while (startIdx !== -1) {
    const nextIdx = buffer.indexOf(delimiter, startIdx + delimiter.length);
    if (nextIdx === -1) break;

    const part = buffer.subarray(startIdx + delimiter.length, nextIdx);
    const headerSplit = part.indexOf(Buffer.from('\r\n\r\n'));
    if (headerSplit !== -1) {
      const headerStr = part.subarray(0, headerSplit).toString('latin1');
      const bodyPart = part.subarray(headerSplit + 4);

      const fnMatch = headerStr.match(/filename="([^"]+)"/i) || headerStr.match(/filename=([^\s;]+)/i);
      if (fnMatch) {
        filename = fnMatch[1];
        // Strip trailing CRLF before next boundary
        let endTrim = bodyPart.length;
        if (endTrim >= 2 && bodyPart[endTrim - 2] === 0x0D && bodyPart[endTrim - 1] === 0x0A) {
          endTrim -= 2;
        }
        fileData = bodyPart.subarray(0, endTrim);
        break;
      }
    }
    startIdx = nextIdx;
  }

  return { buffer: fileData, filename };
}

// Start listening with robust port finding and auto-browser opening
function startServer(portToTry) {
  const srv = server.listen(portToTry, '127.0.0.1', () => {
    const url = `http://127.0.0.1:${portToTry}`;
    console.log(`\n=============================================================`);
    console.log(`🚀 SERVIDOR FORENSE DE CORREO ELECTRONICO ACTIVO EN:`);
    console.log(`   👉 ${url}`);
    console.log(`=============================================================\n`);

    // Open browser automatically
    try {
      const { exec } = require('node:child_process');
      exec(`start "" "${url}"`);
    } catch (e) {
      // ignore
    }
  });

  server.once('error', (err) => {
    if ((err.code === 'EADDRINUSE' || err.code === 'EACCES') && portToTry < 8150) {
      console.warn(`[Servidor] El puerto ${portToTry} no está disponible (${err.code}), intentando con ${portToTry + 1}...`);
      startServer(portToTry + 1);
    } else {
      console.error('[Servidor Error fatal]:', err);
    }
  });
}

if (require.main === module) {
  startServer(PORT);
}

module.exports = { server, runEmailAnalysis };

