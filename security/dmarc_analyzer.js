/**
 * DMARC (Domain-based Message Authentication, Reporting, and Conformance) Protocol Analyzer
 * Evaluates RFC 7489 alignment, policies and authentication disposition.
 */
class DmarcAnalyzer {
  /**
   * Analyze DMARC status combining SPF, DKIM and Authentication-Results
   * @param {Object} headers 
   * @param {Object} spfResult 
   * @param {Object} dkimResult 
   * @param {Object} fromObj 
   * @returns {Object} DMARC analysis result
   */
  static analyze(headers, spfResult, dkimResult, fromObj) {
    const authResults = headers['authentication-results'] || [];
    const fromDomain = (fromObj && fromObj.domain) ? fromObj.domain.toLowerCase().trim() : '';

    let recordedStatus = 'none';
    let recordedDetails = 'No se encontró veredicto DMARC explícito en Authentication-Results.';
    let recordedPolicy = null;
    let recordedAction = null;
    let headerFromDomain = null;

    for (const auth of authResults) {
      const match = auth.match(/\bdmarc=([a-zA-Z]+)(?:\s*\(([^)]*)\))?/i);
      if (match) {
        recordedStatus = match[1].toLowerCase();
        recordedDetails = match[2] || auth;

        const actionMatch = auth.match(/\baction=([a-zA-Z]+)/i);
        if (actionMatch) recordedAction = actionMatch[1].toLowerCase();

        const pMatch = auth.match(/\bp=([a-zA-Z]+)/i);
        if (pMatch) recordedPolicy = pMatch[1].toLowerCase();

        const headerFromMatch = auth.match(/header\.from=([^\s;]+)/i);
        if (headerFromMatch) headerFromDomain = headerFromMatch[1].toLowerCase();
        break;
      }
    }

    // RFC 7489 Alignment Logic:
    // SPF Pass + SPF Alignment = SPF DMARC Success
    const spfPass = spfResult && spfResult.status === 'pass';
    const spfAligned = spfResult && spfResult.isAligned;
    const spfDmarcPass = spfPass && spfAligned;

    // DKIM Pass + DKIM Alignment = DKIM DMARC Success
    const dkimPass = dkimResult && (dkimResult.status === 'pass' || dkimResult.authStatus === 'pass');
    const dkimAligned = dkimResult && dkimResult.hasAlignedSignature;
    const dkimDmarcPass = dkimPass && dkimAligned;

    // Computed DMARC result based on RFC 7489
    let computedStatus = 'fail';
    if (spfDmarcPass || dkimDmarcPass) {
      computedStatus = 'pass';
    } else if (!spfResult?.status || spfResult.status === 'none') {
      computedStatus = 'none';
    }

    // Use recorded status if available from receiving MTA, otherwise computed
    const finalStatus = recordedStatus !== 'none' ? recordedStatus : computedStatus;

    let securityLevel = 'warning';
    let summaryText = '';

    if (finalStatus === 'pass') {
      securityLevel = 'success';
      const reasons = [];
      if (spfDmarcPass) reasons.push('SPF alineado');
      if (dkimDmarcPass) reasons.push('DKIM alineado');
      summaryText = `DMARC Aprobado (PASS): El mensaje supera los requisitos de autenticación y alineación (${reasons.join(' y ')} con el remitente visible).`;
    } else if (finalStatus === 'fail') {
      securityLevel = 'danger';
      summaryText = 'DMARC Fallido (FAIL): Ni SPF ni DKIM están alineados con el dominio visible del remitente. Alto riesgo de falsificación o envío no autorizado.';
    } else {
      securityLevel = 'warning';
      summaryText = 'DMARC No Evaluado / None: No se cuenta con una política DMARC activa o evaluable para el dominio del remitente.';
    }

    // Policy explanation
    let policyExplanation = 'Sin política especificada.';
    if (recordedPolicy === 'reject') {
      policyExplanation = 'REJECT (Rechazar): La política del dominio exige a los servidores de correo descartar inmediatamente mensajes que fallen DMARC.';
    } else if (recordedPolicy === 'quarantine') {
      policyExplanation = 'QUARANTINE (Cuarentena): La política del dominio exige desviar los mensajes fallidos a la carpeta de spam o correo no deseado.';
    } else if (recordedPolicy === 'none') {
      policyExplanation = 'NONE (Monitoreo): El dominio recopila informes de telemetría pero no restringe la entrega de mensajes que fallen la validación.';
    }

    return {
      status: finalStatus,
      recordedStatus,
      computedStatus,
      securityLevel,
      summaryText,
      fromDomain,
      spfDmarcPass,
      dkimDmarcPass,
      policy: recordedPolicy || 'none',
      policyExplanation,
      action: recordedAction || 'none',
      details: recordedDetails
    };
  }
}

module.exports = DmarcAnalyzer;

