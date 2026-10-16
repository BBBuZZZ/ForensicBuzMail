/**
 * SPF (Sender Policy Framework) Protocol Analyzer
 * Evaluates RFC 7208 compliance, Received-SPF headers and alignment.
 */
class SpfAnalyzer {
  /**
   * Analyze SPF status from headers and compare with From domain
   * @param {Object} headers 
   * @param {Object} fromObj { address, domain }
   * @param {string} returnPath 
   * @returns {Object} SPF analysis result
   */
  static analyze(headers, fromObj, returnPath) {
    const receivedSpfHeaders = headers['received-spf'] || [];
    const authResultsHeaders = headers['authentication-results'] || [];

    let status = 'none';
    let clientIp = null;
    let sender = null;
    let domain = null;
    let details = 'No se encontraron registros de evaluación SPF en las cabeceras.';
    let rawHeader = null;

    // First inspect Received-SPF if available as it contains raw MTA transport details
    for (const rSpf of receivedSpfHeaders) {
      rawHeader = rSpf;
      const firstWordMatch = rSpf.match(/^([a-zA-Z]+)/);
      if (firstWordMatch && status === 'none') {
        status = firstWordMatch[1].toLowerCase();
      }

      const ipMatch = rSpf.match(/client-ip=([0-9a-fA-F.:]+)/i) || 
                      rSpf.match(/designates\s+([0-9a-fA-F.:]+)/i) ||
                      rSpf.match(/(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/);
      if (ipMatch && !clientIp) clientIp = ipMatch[1];

      const senderMatch = rSpf.match(/envelope-from=([^\s;]+)/i) || 
                          rSpf.match(/identity=([^\s;]+)/i) ||
                          rSpf.match(/domain of\s+([^\s;]+)/i);
      if (senderMatch && !sender) {
        sender = senderMatch[1].replace(/[<>]/g, '');
      }

      if (details === 'No se encontraron registros de evaluación SPF en las cabeceras.') {
        details = rSpf;
      }
    }

    // Next inspect Authentication-Results for authoritative receiver verdict
    for (const auth of authResultsHeaders) {
      const match = auth.match(/\bspf=([a-zA-Z]+)(?:\s*\(([^)]*)\))?/i);
      if (match) {
        status = match[1].toLowerCase();
        if (match[2]) details = match[2];
        if (!rawHeader) rawHeader = auth;

        if (!clientIp) {
          const ipMatch = auth.match(/client-ip=([0-9a-fA-F.:]+)/i) ||
                          auth.match(/designates\s+([0-9a-fA-F.:]+)/i) ||
                          auth.match(/(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/);
          if (ipMatch) clientIp = ipMatch[1];
        }

        if (!sender) {
          const mailfromMatch = auth.match(/smtp\.mailfrom=([^\s;]+)/i) || 
                                auth.match(/domain of\s+([^\s;]+)/i) ||
                                auth.match(/identity=([^\s;]+)/i);
          if (mailfromMatch) sender = mailfromMatch[1].replace(/[<>]/g, '');
        }
        break;
      }
    }

    // Extract domain from sender, details or returnPath
    if (!domain) {
      if (sender) {
        domain = sender.includes('@') ? sender.split('@')[1] : sender;
      } else if (returnPath && returnPath.includes('@')) {
        domain = returnPath.replace(/[<>]/g, '').split('@')[1];
      } else {
        const dMatch = details.match(/\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/);
        if (dMatch) domain = dMatch[1];
      }
    }

    // Clean domain
    if (domain) {
      domain = domain.toLowerCase().trim().replace(/^[.]+/, '');
    }

    // Domain Alignment Check (DMARC SPF Alignment)
    const fromDomain = (fromObj && fromObj.domain) ? fromObj.domain.toLowerCase().trim() : '';
    let isAligned = false;
    let alignmentType = 'none';

    if (fromDomain && domain) {
      if (fromDomain === domain) {
        isAligned = true;
        alignmentType = 'strict';
      } else if (fromDomain.endsWith('.' + domain) || domain.endsWith('.' + fromDomain)) {
        isAligned = true;
        alignmentType = 'relaxed';
      } else {
        isAligned = false;
        alignmentType = 'fail';
      }
    }

    // Security Assessment
    let securityLevel = 'warning';
    let summaryText = '';

    switch (status) {
      case 'pass':
        securityLevel = isAligned ? 'success' : 'warning';
        summaryText = isAligned
          ? 'SPF Válido y Alineado: La IP de envío está explícitamente autorizada por la política SPF del dominio remitente.'
          : 'SPF Válido sin Alineación: La IP está autorizada para el dominio envelope, pero no coincide con el dominio visible del From.';
        break;
      case 'softfail':
        securityLevel = 'warning';
        summaryText = 'SPF Softfail (~all): La IP remitente probablemente no está autorizada, pero el dominio solicita no rechazar tajantemente.';
        break;
      case 'fail':
        securityLevel = 'danger';
        summaryText = 'SPF Fail (-all): La dirección IP NO está autorizada para emitir correos en nombre del dominio remitente (Sospecha de Spoofing).';
        break;
      case 'neutral':
        securityLevel = 'info';
        summaryText = 'SPF Neutral (?all): El dominio no declara si la IP remitente está o no autorizada.';
        break;
      case 'none':
        securityLevel = 'danger';
        summaryText = 'Sin Registro SPF: No se encontraron registros de política SPF publicados o evaluados para el remitente.';
        break;
      case 'permerror':
        securityLevel = 'danger';
        summaryText = 'Error Permanente SPF: El registro SPF del dominio tiene errores de sintaxis o excedió el límite de 10 lookups DNS.';
        break;
      case 'temperror':
        securityLevel = 'warning';
        summaryText = 'Error Temporal SPF: Ocurrió un error temporal (ej. fallo DNS transitorio) durante la verificación SPF.';
        break;
      default:
        securityLevel = 'warning';
        summaryText = `Estado SPF: ${status}`;
    }

    return {
      status,
      securityLevel,
      summaryText,
      clientIp: clientIp || 'No especificada',
      sender: sender || returnPath || 'Desconocido',
      spfDomain: domain || 'No detectado',
      fromDomain: fromDomain || 'No detectado',
      isAligned,
      alignmentType,
      details,
      rawHeader: rawHeader || ''
    };
  }
}

module.exports = SpfAnalyzer;

