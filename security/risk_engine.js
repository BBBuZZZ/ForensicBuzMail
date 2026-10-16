/**
 * Forensic Security Risk Assessment Engine
 * Calculates visual risk score (0-100), risk tiers, and specific threat vectors.
 */
class RiskEngine {
  /**
   * Evaluate overall email security risk
   * @param {Object} email 
   * @param {Object} spf 
   * @param {Object} dkim 
   * @param {Object} dmarc 
   * @param {Object} network 
   * @returns {Object} Risk evaluation details
   */
  static evaluate(email, spf, dkim, dmarc, network) {
    let score = 0;
    const findings = [];

    const fromAddr = (email.from?.address || '').toLowerCase();
    const fromDomain = (email.from?.domain || '').toLowerCase();
    const fromName = (email.from?.name || '').toLowerCase();
    const returnPath = (email.returnPath || '').toLowerCase();
    const replyToAddr = (email.replyTo?.address || '').toLowerCase();
    const replyToDomain = (email.replyTo?.domain || '').toLowerCase();

    // 1. SPF EVALUATION
    if (spf.status === 'fail') {
      score += 35;
      findings.push({
        severity: 'critical',
        points: 35,
        protocol: 'SPF',
        title: 'Fallo Crítico SPF (fail)',
        description: 'La IP emisora está explícitamente prohibida por la política SPF del dominio (-all).'
      });
    } else if (spf.status === 'softfail') {
      score += 20;
      findings.push({
        severity: 'high',
        points: 20,
        protocol: 'SPF',
        title: 'SPF Softfail (~all)',
        description: 'El dominio remitente reporta que la IP probablemente no está autorizada para emitir.'
      });
    } else if (spf.status === 'none' || spf.status === 'neutral') {
      score += 15;
      findings.push({
        severity: 'medium',
        points: 15,
        protocol: 'SPF',
        title: 'Sin Protección SPF Efectiva',
        description: 'El dominio no tiene registro SPF o tiene un registro neutral (?all), permitiendo spoofing.'
      });
    }

    if (spf.status === 'pass' && !spf.isAligned) {
      score += 15;
      findings.push({
        severity: 'medium',
        points: 15,
        protocol: 'SPF',
        title: 'Desalineación de Dominio SPF',
        description: `El envelope sender (${spf.spfDomain}) no coincide con el dominio visible (${fromDomain}).`
      });
    }

    // 2. DKIM EVALUATION
    if (dkim.status === 'fail') {
      score += 35;
      findings.push({
        severity: 'critical',
        points: 35,
        protocol: 'DKIM',
        title: 'Firma DKIM Inválida / Corrupta',
        description: 'La firma digital no es válida, indicando que el contenido o cabeceras fueron manipulados.'
      });
    } else if (!dkim.hasSignatures) {
      score += 25;
      findings.push({
        severity: 'high',
        points: 25,
        protocol: 'DKIM',
        title: 'Ausencia de Firma Criptográfica DKIM',
        description: 'El correo no posee firmas digitales para verificar la integridad del mensaje y la identidad.'
      });
    } else if (dkim.signatures.some(s => s.isWeakAlgo)) {
      score += 15;
      findings.push({
        severity: 'medium',
        points: 15,
        protocol: 'DKIM',
        title: 'Algoritmo Criptográfico Obsoleto (SHA-1)',
        description: 'Se utilizó SHA-1 en la firma DKIM, vulnerable a colisiones criptográficas.'
      });
    }

    if (dkim.hasSignatures && !dkim.hasAlignedSignature) {
      score += 15;
      findings.push({
        severity: 'medium',
        points: 15,
        protocol: 'DKIM',
        title: 'Desalineación de Firma DKIM',
        description: 'La firma DKIM pertenece a un dominio de terceros y no está alineada con el remitente visible.'
      });
    }

    // 3. DMARC EVALUATION
    if (dmarc.status === 'fail') {
      score += 30;
      findings.push({
        severity: 'critical',
        points: 30,
        protocol: 'DMARC',
        title: 'Fallo Total DMARC',
        description: 'El correo no superó ni la alineación SPF ni la alineación DKIM con el dominio visible.'
      });
    } else if (dmarc.status === 'none') {
      score += 10;
      findings.push({
        severity: 'low',
        points: 10,
        protocol: 'DMARC',
        title: 'Ausencia de Política DMARC',
        description: 'El dominio no publica directivas DMARC para proteger su marca contra suplantaciones.'
      });
    }

    // 4. DISPLAY NAME SPOOFING & IDENTITY INCONSISTENCIES
    const targetBrands = [
      { keyword: 'google', expectedDomain: 'google.' },
      { keyword: 'microsoft', expectedDomain: 'microsoft.' },
      { keyword: 'apple', expectedDomain: 'apple.' },
      { keyword: 'amazon', expectedDomain: 'amazon.' },
      { keyword: 'paypal', expectedDomain: 'paypal.' },
      { keyword: 'netflix', expectedDomain: 'netflix.' },
      { keyword: 'santander', expectedDomain: 'santander.' },
      { keyword: 'bbva', expectedDomain: 'bbva.' },
      { keyword: 'caixabank', expectedDomain: 'caixabank.' },
      { keyword: 'hacienda', expectedDomain: 'agenciatributaria.' },
      { keyword: 'dgt', expectedDomain: 'dgt.' }
    ];

    for (const b of targetBrands) {
      const isBrandInName = fromName.includes(b.keyword);
      const isBrandInDomain = fromDomain.includes(b.keyword) || fromDomain.includes(b.expectedDomain);

      // Case A: Name mentions brand, but domain is completely different
      if (isBrandInName && !isBrandInDomain) {
        score += 30;
        findings.push({
          severity: 'critical',
          points: 30,
          protocol: 'Identidad',
          title: `Suplantación en Nombre Visible (Display Name Spoofing: "${b.keyword.toUpperCase()}")`,
          description: `El nombre visible muestra "${fromName}", pero la dirección real del emisor pertenece a un dominio no relacionado (${fromDomain}).`
        });
        break;
      }

      // Case B: From address claims to be brand domain, but SPF or DMARC failed
      if (isBrandInDomain && (spf.status === 'fail' || dmarc.status === 'fail')) {
        score += 30;
        findings.push({
          severity: 'critical',
          points: 30,
          protocol: 'Identidad',
          title: `Suplantación Directa de Dominio de Marca (Brand Spoofing: "${b.keyword.toUpperCase()}")`,
          description: `El remitente visible afirma pertenecer a ${fromDomain}, pero la autenticación criptográfica SPF/DMARC ha fallado categóricamente.`
        });
        break;
      }
    }

    // Return-Path vs From Domain Mismatch
    if (returnPath && returnPath.includes('@')) {
      const rpDomain = returnPath.replace(/[<>]/g, '').split('@')[1]?.toLowerCase();
      if (rpDomain && fromDomain && rpDomain !== fromDomain && !fromDomain.endsWith('.' + rpDomain)) {
        score += 15;
        findings.push({
          severity: 'medium',
          points: 15,
          protocol: 'Identidad',
          title: 'Discrepancia entre From y Return-Path',
          description: `Las respuestas y rebotes de error se dirigen a ${rpDomain}, no al dominio del remitente (${fromDomain}).`
        });
      }
    }

    // Reply-To mismatch
    if (replyToAddr && replyToDomain && fromDomain && replyToDomain !== fromDomain) {
      score += 20;
      findings.push({
        severity: 'high',
        points: 20,
        protocol: 'Identidad',
        title: 'Desviación de Respuesta (Reply-To Mismatch)',
        description: `Las respuestas del usuario serán enviadas a una dirección diferente (${replyToAddr}), técnica común en phishing.`
      });
    }

    // 5. ATTACHMENT RISK
    const attachments = email.attachments || [];
    for (const att of attachments) {
      if (att.isSuspicious) {
        score += 40;
        findings.push({
          severity: 'critical',
          points: 40,
          protocol: 'Adjuntos',
          title: `Adjunto de Alto Riesgo Detectado (${att.filename})`,
          description: 'El correo contiene un archivo ejecutable o script potencialmente malicioso para la máquina.'
        });
      }
    }

    // Clamp score between 0 and 100
    const finalScore = Math.min(100, Math.max(0, score));

    // Determine level
    let level = 'low';
    let label = 'Bajo Riesgo (Seguro)';
    let color = '#10b981'; // Green emerald
    let badgeClass = 'risk-badge-low';
    let recommendations = 'El correo supera los protocolos principales de seguridad o no presenta anomalías graves.';

    if (finalScore >= 80) {
      level = 'critical';
      label = 'Riesgo Crítico (Malicioso)';
      color = '#ef4444'; // Red
      badgeClass = 'risk-badge-critical';
      recommendations = '¡PELIGRO! NO descargue adjuntos ni pulse enlaces. Este correo presenta indicadores consistentes de phishing o suplantación deliberada.';
    } else if (finalScore >= 51) {
      level = 'high';
      label = 'Alto Riesgo (Sospechoso)';
      color = '#f97316'; // Orange
      badgeClass = 'risk-badge-high';
      recommendations = 'Precaución extrema: Se detectaron fallos significativos en la autenticación del remitente o anomalías en la identidad.';
    } else if (finalScore >= 21) {
      level = 'medium';
      label = 'Riesgo Moderado (Precaución)';
      color = '#f59e0b'; // Amber
      badgeClass = 'risk-badge-medium';
      recommendations = 'El correo carece de ciertas firmas de integridad o tiene configuraciones permisivas de DNS.';
    }

    return {
      score: finalScore,
      level,
      label,
      color,
      badgeClass,
      recommendations,
      findingsCount: findings.length,
      findings
    };
  }
}

module.exports = RiskEngine;

