/**
 * End-to-end Integration Test for HTTP Server and API Endpoints
 */
const http = require('node:http');
const { server } = require('../server');

const TEST_PORT = 3199;

function request(method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port: TEST_PORT,
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, rawBody: data });
        }
      });
    });
    req.on('error', reject);
    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

async function runServerTests() {
  console.log('🧪 Iniciando pruebas de endpoints HTTP...');
  server.listen(TEST_PORT, '127.0.0.1', async () => {
    try {
      // 1. GET /api/samples
      const samplesRes = await request('GET', '/api/samples');
      console.log('1. /api/samples -> HTTP', samplesRes.status, 'Muestras:', samplesRes.body.data.map(s => s.name));
      if (samplesRes.status !== 200 || samplesRes.body.data.length < 2) {
        throw new Error('Fallo al obtener muestras');
      }

      // 2. POST /api/samples/phishing_spoof.eml
      const analyzeRes = await request('POST', '/api/samples/phishing_spoof.eml');
      console.log('2. /api/samples/phishing_spoof.eml -> HTTP', analyzeRes.status, 'Score:', analyzeRes.body.data.risk.score, 'Level:', analyzeRes.body.data.risk.level);
      if (analyzeRes.status !== 200 || analyzeRes.body.data.risk.level !== 'critical') {
        throw new Error('Fallo en análisis de muestra de phishing');
      }

      // 3. POST /api/samples/invoice_sample.msg
      const msgRes = await request('POST', '/api/samples/invoice_sample.msg');
      console.log('3. /api/samples/invoice_sample.msg -> HTTP', msgRes.status, 'Asunto:', msgRes.body.data.email.subject);
      if (msgRes.status !== 200 || !msgRes.body.data.email.subject.includes('Factura')) {
        throw new Error('Fallo en análisis de muestra .msg');
      }

      // 4. GET /api/history
      const historyRes = await request('GET', '/api/history');
      console.log('4. /api/history -> HTTP', historyRes.status, 'Registros en historial:', historyRes.body.data.length);
      if (historyRes.status !== 200 || historyRes.body.data.length < 2) {
        throw new Error('Fallo al leer historial de SQLite');
      }

      // 5. GET /api/stats
      const statsRes = await request('GET', '/api/stats');
      console.log('5. /api/stats -> HTTP', statsRes.status, 'Total analizados:', statsRes.body.data.total);

      console.log('\n✅ ¡TODOS LOS ENDPOINTS HTTP RESPONDIERON EXITOSAMENTE!');
      process.exit(0);
    } catch (err) {
      console.error('❌ Error en pruebas de endpoints:', err);
      process.exit(1);
    } finally {
      server.close();
    }
  });
}

runServerTests();

