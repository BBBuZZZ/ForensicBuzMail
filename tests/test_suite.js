/**
 * Automated Test Suite for Email Forensics & Security Analyzer
 */
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert');

const MimeParser = require('../parsers/mime_parser');
const MsgParser = require('../parsers/msg_parser');
const HeaderAnalyzer = require('../parsers/header_analyzer');
const SpfAnalyzer = require('../security/spf_analyzer');
const DkimAnalyzer = require('../security/dkim_analyzer');
const DmarcAnalyzer = require('../security/dmarc_analyzer');
const RiskEngine = require('../security/risk_engine');
const ForensicDatabase = require('../database');
const IpGeolocator = require('../security/ip_geolocator');

const SAMPLES_DIR = path.join(__dirname, '..', 'samples');

async function runTestSuite() {
  console.log('====================================================');
  console.log('🧪 INICIANDO TEST SUITE FORENSE AUTOMATIZADO');
  console.log('====================================================\n');

  let passed = 0;
  let failed = 0;

  function test(name, fn) {
    try {
      fn();
      console.log(`  ✅ [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ [FAIL] ${name}`);
      console.error(`     Error: ${err.message}`);
      failed++;
    }
  }

  // 1. TEST MIME PARSER WITH LEGITIMATE EMAIL
  const legitBuf = fs.readFileSync(path.join(SAMPLES_DIR, 'legitimate_email.eml'));
  let legitEmail;

  test('MimeParser: Decodificación de cabeceras RFC 5322 en legitimate_email.eml', () => {
    legitEmail = MimeParser.parse(legitBuf);
    assert.ok(legitEmail.subject.includes('Alerta de seguridad'), 'El asunto no coincide');
    assert.strictEqual(legitEmail.from.domain, 'google.com', 'El dominio del remitente no es google.com');
    assert.ok(legitEmail.headers['received-spf'], 'Falta cabecera received-spf');
    assert.ok(legitEmail.textBody.includes('Se ha detectado un nuevo inicio de sesión'), 'Falta cuerpo de texto');
  });

  // 2. TEST SPF ANALYZER
  let legitSpf;
  test('SpfAnalyzer: Evaluación de SPF Pass y Alineación Estricta', () => {
    legitSpf = SpfAnalyzer.analyze(legitEmail.headers, legitEmail.from, legitEmail.returnPath);
    assert.strictEqual(legitSpf.status, 'pass', 'SPF debió resultar pass');
    assert.strictEqual(legitSpf.clientIp, '209.85.220.41', 'IP cliente SPF incorrecta');
    assert.strictEqual(legitSpf.isAligned, true, 'SPF debió estar alineado con From');
    assert.strictEqual(legitSpf.securityLevel, 'success');
  });

  // 3. TEST DKIM ANALYZER
  let legitDkim;
  test('DkimAnalyzer: Extracción de firmas y validación de alineación', () => {
    legitDkim = DkimAnalyzer.analyze(legitEmail.headers, legitEmail.from);
    assert.strictEqual(legitDkim.status, 'pass', 'DKIM debió ser pass');
    assert.ok(legitDkim.signaturesCount >= 1, 'Debió encontrar firmas DKIM');
    assert.strictEqual(legitDkim.hasAlignedSignature, true, 'La firma DKIM debió estar alineada con google.com');
    assert.strictEqual(legitDkim.securityLevel, 'success');
  });

  // 4. TEST DMARC ANALYZER
  let legitDmarc;
  test('DmarcAnalyzer: Verificación de política DMARC y alineación dual', () => {
    legitDmarc = DmarcAnalyzer.analyze(legitEmail.headers, legitSpf, legitDkim, legitEmail.from);
    assert.strictEqual(legitDmarc.status, 'pass', 'DMARC debió resultar pass');
    assert.strictEqual(legitDmarc.spfDmarcPass, true, 'SPF DMARC debió pasar');
    assert.strictEqual(legitDmarc.dkimDmarcPass, true, 'DKIM DMARC debió pasar');
    assert.strictEqual(legitDmarc.securityLevel, 'success');
  });

  // 5. TEST NETWORK HOPS (SMTP Relays & Origin IP)
  let legitNetwork;
  test('HeaderAnalyzer: Rastro de saltos Received y detección de IP de origen', () => {
    legitNetwork = HeaderAnalyzer.analyzeNetworkRoute(legitEmail.headers);
    assert.ok(legitNetwork.totalHops >= 2, 'Debieron detectarse al menos 2 saltos');
    assert.strictEqual(legitNetwork.originIp, '209.85.220.41', 'La IP de origen debe ser 209.85.220.41');
    assert.strictEqual(legitNetwork.isOriginPrivate, false, 'La IP de Google no es privada');
  });

  // 6. TEST RISK ENGINE ON LEGITIMATE EMAIL
  test('RiskEngine: Score bajo para correo legítimo auténtico', () => {
    const risk = RiskEngine.evaluate(legitEmail, legitSpf, legitDkim, legitDmarc, legitNetwork);
    assert.ok(risk.score <= 20, `El score (${risk.score}) debió ser <= 20 para correo legítimo`);
    assert.strictEqual(risk.level, 'low', 'El nivel de riesgo debió ser low');
  });

  // 7. TEST PHISHING & SPOOFING EMAIL
  const phishBuf = fs.readFileSync(path.join(SAMPLES_DIR, 'phishing_spoof.eml'));
  let phishEmail;

  test('MimeParser: Detección de adjunto ejecutable sospechoso en phishing_spoof.eml', () => {
    phishEmail = MimeParser.parse(phishBuf);
    assert.strictEqual(phishEmail.from.name, 'PayPal Security Center');
    assert.strictEqual(phishEmail.attachments.length, 1, 'Debió encontrar 1 adjunto');
    const att = phishEmail.attachments[0];
    assert.strictEqual(att.filename, 'Urgente_Detalle_Cuenta.pdf.exe');
    assert.strictEqual(att.isSuspicious, true, 'El adjunto .pdf.exe debe ser marcado sospechoso');
    assert.ok(att.sha256 && att.sha256.length === 64, 'Falta hash SHA-256');
  });

  test('SpfAnalyzer & DmarcAnalyzer: Detección de Spoofing y Fallo SPF/DMARC', () => {
    const phishSpf = SpfAnalyzer.analyze(phishEmail.headers, phishEmail.from, phishEmail.returnPath);
    assert.strictEqual(phishSpf.status, 'fail', 'SPF debe fallar en phishing');
    assert.strictEqual(phishSpf.clientIp, '185.220.101.5', 'IP de origen maliciosa incorrecta');

    const phishDkim = DkimAnalyzer.analyze(phishEmail.headers, phishEmail.from);
    assert.strictEqual(phishDkim.hasSignatures, false, 'No debe tener firma DKIM válida');

    const phishDmarc = DmarcAnalyzer.analyze(phishEmail.headers, phishSpf, phishDkim, phishEmail.from);
    assert.strictEqual(phishDmarc.status, 'fail', 'DMARC debe fallar por completo');

    const phishNetwork = HeaderAnalyzer.analyzeNetworkRoute(phishEmail.headers);
    assert.strictEqual(phishNetwork.originIp, '185.220.101.5', 'IP de origen debe ser la del relay malicioso');

    const phishRisk = RiskEngine.evaluate(phishEmail, phishSpf, phishDkim, phishDmarc, phishNetwork);
    assert.ok(phishRisk.score >= 80, `El score de riesgo (${phishRisk.score}) debe ser >= 80 (Crítico)`);
    assert.strictEqual(phishRisk.level, 'critical', 'El nivel de riesgo debe ser critical');
    assert.ok(phishRisk.findings.some(f => f.title.includes('Suplantación')), 'Debe detectar Display Name Spoofing');
    assert.ok(phishRisk.findings.some(f => f.title.includes('Adjunto de Alto Riesgo')), 'Debe detectar adjunto ejecutable');
  });

  // 8. TEST MSG PARSER (OUTLOOK CFBF OLE2)
  const msgPath = path.join(SAMPLES_DIR, 'invoice_sample.msg');
  if (fs.existsSync(msgPath)) {
    test('MsgParser: Lectura de estructura binaria CFBF / OLE2 de Outlook .msg', () => {
      const msgBuf = fs.readFileSync(msgPath);
      assert.strictEqual(MsgParser.isMsgFile(msgBuf), true, 'Firma OLE2 CFBF no reconocida');

      const parsedMsg = MsgParser.parse(msgBuf);
      assert.ok(parsedMsg.subject.includes('Factura de Servicios Profesionales'), 'Asunto MSG no extraído');
      assert.strictEqual(parsedMsg.from.domain, 'empresa-aliada.es', 'Dominio remitente MSG no coincide');
      assert.ok(parsedMsg.textBody.includes('cierre de operaciones'), 'Cuerpo de texto MSG no extraído');
      assert.ok(parsedMsg.attachments.length >= 1, 'Adjunto en MSG no extraído');
      assert.strictEqual(parsedMsg.attachments[0].filename, 'Factura_48291.pdf');
    });
  }

  // 9. TEST SQLITE / PERSISTENCE DATABASE
  test('ForensicDatabase: Registro, consulta por búsqueda y estadísticas', () => {
    const testDbDir = path.join(__dirname, '..', 'data');
    const db = new ForensicDatabase(testDbDir);

    const testItem = {
      filename: 'prueba_unidad.eml',
      fileType: 'eml',
      fileSize: 1024,
      email: {
        subject: 'Prueba de Integridad SQLite',
        from: { address: 'soc@cybersecurity.local' },
        to: [{ address: 'incident@cybersecurity.local' }],
        attachments: []
      },
      network: { originIp: '198.51.100.22' },
      spf: { status: 'pass' },
      dkim: { status: 'pass' },
      dmarc: { status: 'pass' },
      risk: { score: 10, level: 'low' }
    };

    const savedId = db.saveAnalysis(testItem);
    assert.ok(savedId, 'No se generó ID de registro');

    const fetched = db.getAnalysisById(savedId);
    assert.ok(fetched, 'No se pudo recuperar el análisis por ID');
    assert.strictEqual(fetched.email.subject, 'Prueba de Integridad SQLite');

    const searchResults = db.getHistory(10, 0, 'Prueba de Integridad');
    assert.ok(searchResults.length >= 1, 'Búsqueda en base de datos falló');

    const stats = db.getStats();
    assert.ok(stats.total >= 1, 'Estadísticas no calculadas');

    db.deleteAnalysis(savedId);
    const afterDelete = db.getAnalysisById(savedId);
    assert.strictEqual(afterDelete, null, 'El registro no fue eliminado correctamente');
  });

  // 10. TEST GMAIL PLAIN TEXT COPIES (SHOW ORIGINAL + SUMMARY TABLE + SPANISH UI)
  test('MimeParser: Normalización y parseo de copias en texto plano de Gmail', () => {
    // 10.1 Gmail Mostrar original (Summary table + raw headers)
    const gmailFull = `ID del mensaje\t<alert-123@google.com>
Creado el:\t14 de octubre de 2026, 17:30
De:\tGoogle Security <noreply-security@google.com>
Para:\tvictima@empresa.com
Asunto:\tAviso urgente de inicio de sesión
SPF:\tPASS con la IP 209.85.220.41 Más información

Delivered-To: victima@empresa.com
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mx.google.com;
From: Google Security <noreply-security@google.com>
To: victima@empresa.com
Subject: Aviso urgente de inicio de sesión

Contenido del correo en texto.`;

    const parsedA = MimeParser.parse(gmailFull);
    assert.strictEqual(parsedA.subject, 'Aviso urgente de inicio de sesión');
    assert.strictEqual(parsedA.from.address, 'noreply-security@google.com');

    // 10.2 Gmail ONLY summary table
    const gmailSummaryOnly = `ID del mensaje\t<summary-456@google.com>
Creado el:\t14 de octubre de 2026, 18:00
De:\tNotificaciones Google <soporte@google.com>
Para:\tusuario@empresa.com
Asunto:\tVerificación de dos pasos activada
SPF:\tPASS con la IP 209.85.220.41 Más información
DKIM:\t'PASS' con el dominio google.com Más información
DMARC:\t'PASS' Más información`;

    const parsedB = MimeParser.parse(gmailSummaryOnly);
    assert.strictEqual(parsedB.subject, 'Verificación de dos pasos activada');
    assert.strictEqual(parsedB.from.address, 'soporte@google.com');
    assert.strictEqual(parsedB.messageId, '<summary-456@google.com>');

    // 10.3 Gmail Spanish Web UI Copy (De:, Para:, Asunto:, Fecha:)
    const gmailWebCopy = `De: Seguridad Santander <avisos@santander-alerta.com>
Para: cliente@correo.es
Asunto: Bloqueo preventivo de tarjeta
Fecha: 16 oct 2026, 09:15

Estimado cliente, su tarjeta ha sido bloqueada.`;

    const parsedC = MimeParser.parse(gmailWebCopy);
    assert.strictEqual(parsedC.subject, 'Bloqueo preventivo de tarjeta');
    assert.strictEqual(parsedC.from.address, 'avisos@santander-alerta.com');
  });

  // 11. TEST OFFLINE IP GEOLOCATION & REGIONAL REGISTRY ATTRIBUTION
  test('IpGeolocator: Clasificación offline de IP, RIR y Redes Corporativas', () => {
    // Google Workspace IP
    const geoGoogle = IpGeolocator.analyzeOffline('209.85.220.41');
    assert.strictEqual(geoGoogle.isPrivate, false);
    assert.strictEqual(geoGoogle.country, 'Estados Unidos');
    assert.strictEqual(geoGoogle.flag, '🇺🇸');
    assert.ok(geoGoogle.org.includes('Google'), 'Organización de Google no identificada');
    assert.strictEqual(geoGoogle.rir, 'ARIN');

    // Telefónica España IP
    const geoTelef = IpGeolocator.analyzeOffline('80.58.61.250');
    assert.strictEqual(geoTelef.country, 'España');
    assert.strictEqual(geoTelef.flag, '🇪🇸');
    assert.ok(geoTelef.org.includes('Telefónica'), 'Telefónica no identificada');
    assert.strictEqual(geoTelef.rir, 'RIPE NCC');

    // Private LAN IP
    const geoPrivate = IpGeolocator.analyzeOffline('192.168.1.100');
    assert.strictEqual(geoPrivate.isPrivate, true);
    assert.strictEqual(geoPrivate.scope, 'Red Privada Local (RFC 1918)');

    // Tor Relay prefix
    const geoTor = IpGeolocator.analyzeOffline('185.220.101.5');
    assert.ok(geoTor.org.includes('Tor'), 'Nodo Tor no detectado');
  });

  console.log('\n====================================================');
  console.log(`📊 RESULTADOS DEL TEST SUITE:`);
  console.log(`   Pruebas Exitosas: ${passed}`);
  console.log(`   Pruebas Fallidas: ${failed}`);
  console.log('====================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

if (require.main === module) {
  runTestSuite().catch(err => {
    console.error('Fallo inesperado en test suite:', err);
    process.exit(1);
  });
}

module.exports = { runTestSuite };

