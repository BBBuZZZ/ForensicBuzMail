/**
 * DKIM (DomainKeys Identified Mail) Protocol Analyzer
 * Evaluates RFC 6376 signatures, tags, algorithm strength and alignment.
 */
class DkimAnalyzer {
  /**
   * Analyze DKIM signatures and authentication results
   * @param {Object} headers 
   * @param {Object} fromObj { address, domain }
   * @returns {Object} DKIM analysis result
   */
  static analyze(headers, fromObj) {
    const rawSignatures = headers['dkim-signature'] || [];
    const authResults = headers['authentication-results'] || [];

    const signatures = [];
    const fromDomain = (fromObj && fromObj.domain) ? fromObj.domain.toLowerCase().trim() : '';

    // Parse all DKIM-Signature headers
    for (const rawSig of rawSignatures) {
      const tags = this.parseDkimTags(rawSig);
      const signDomain = (tags.d || '').toLowerCase().trim();

      // Check alignment with From domain
      let isAligned = false;
      let alignmentType = 'none';

      if (fromDomain && signDomain) {
        if (fromDomain === signDomain) {
          isAligned = true;
          alignmentType = 'strict';
        } else if (fromDomain.endsWith('.' + signDomain) || signDomain.endsWith('.' + fromDomain)) {
          isAligned = true;
          alignmentType = 'relaxed';
        } else {
          isAligned = false;
          alignmentType = 'fail';
        }
      }

      // Check algorithm security
      const algo = (tags.a || '').toLowerCase();
      const isWeakAlgo = algo.includes('sha1');

      signatures.push({
        version: tags.v || '1',
        algorithm: tags.a || 'Desconocido',
        domain: signDomain || 'No especificado',
        selector: tags.s || 'No especificado',
        canonicalization: tags.c || 'simple/simple',
        signedHeaders: tags.h ? tags.h.split(':').map(h => h.trim()) : [],
        bodyHash: tags.bh || '',
        signatureData: tags.b ? tags.b.slice(0, 32) + '...' : '',
        timestamp: tags.t ? new Date(parseInt(tags.t, 10) * 1000).toISOString() : null,
        expiration: tags.x ? new Date(parseInt(tags.x, 10) * 1000).toISOString() : null,
        isAligned,
        alignmentType,
        isWeakAlgo,
        raw: rawSig
      });
    }

    // Determine status from Authentication-Results
    let authStatus = 'none';
    let authDetails = 'No se encontró veredicto DKIM en Authentication-Results.';
    let authDomain = null;

    for (const auth of authResults) {
      const match = auth.match(/\bdkim=([a-zA-Z]+)(?:\s*\(([^)]*)\))?/i);
      if (match) {
        authStatus = match[1].toLowerCase();
        authDetails = match[2] || auth;

        const headerDMatch = auth.match(/header\.d=([^\s;]+)/i) || auth.match(/header\.i=@?([^\s;]+)/i);
        if (headerDMatch) authDomain = headerDMatch[1].toLowerCase();
        break;
      }
    }

    // Overall verdict
    const hasSignatures = signatures.length > 0;
    const hasAlignedSignature = signatures.some(s => s.isAligned);
    const hasWeak = signatures.some(s => s.isWeakAlgo);

    let status = authStatus !== 'none' ? authStatus : (hasSignatures ? 'signed_unverified' : 'none');
    let securityLevel = 'warning';
    let summaryText = '';

    if (status === 'pass') {
      if (hasAlignedSignature || (authDomain && fromDomain && (authDomain === fromDomain || fromDomain.endsWith('.' + authDomain)))) {
        securityLevel = 'success';
        summaryText = 'DKIM Válido y Alineado: La firma criptográfica es auténtica y el dominio firmante coincide con el remitente visible.';
      } else {
        securityLevel = 'warning';
        summaryText = 'DKIM Válido con Terceros (Sin Alineación): La firma es íntegra pero fue firmada por un dominio distinto al remitente (posible pasarela o relay).';
      }
    } else if (status === 'fail') {
      securityLevel = 'danger';
      summaryText = 'Fallo Crítico DKIM: La firma digital del mensaje es INVÁLIDA o el cuerpo/cabeceras han sido alterados en tránsito.';
    } else if (status === 'signed_unverified') {
      securityLevel = hasAlignedSignature ? 'info' : 'warning';
      summaryText = `Mensaje con ${signatures.length} firma(s) DKIM presente(s). Sin cabecera receptora de verificación automática en tránsito.`;
    } else {
      securityLevel = 'danger';
      summaryText = 'Sin Firma DKIM: El mensaje no incluye cabeceras criptográficas DKIM que garanticen la integridad del contenido.';
    }

    if (hasWeak) {
      summaryText += ' [ADVERTENCIA: Se detectó algoritmo criptográfico débil SHA-1 vulnerable a colisiones].';
    }

    return {
      status,
      securityLevel,
      summaryText,
      hasSignatures,
      hasAlignedSignature,
      signaturesCount: signatures.length,
      signatures,
      authStatus,
      authDomain,
      authDetails,
      fromDomain
    };
  }

  /**
   * Parse DKIM-Signature tag=value pairs
   */
  static parseDkimTags(sigHeader) {
    const tags = {};
    const pairs = sigHeader.split(';');
    for (const pair of pairs) {
      const eqIdx = pair.indexOf('=');
      if (eqIdx > 0) {
        const key = pair.slice(0, eqIdx).trim().toLowerCase();
        const val = pair.slice(eqIdx + 1).trim();
        tags[key] = val;
      }
    }
    return tags;
  }
}

module.exports = DkimAnalyzer;

