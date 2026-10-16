/**
 * UI Component Renderers for Email Forensics Analyzer
 */
const Components = {
  /**
   * Render Risk Level Badge
   */
  renderRiskBadge(level, label) {
    let cls = 'badge-success';
    if (level === 'critical') cls = 'badge-danger';
    else if (level === 'high') cls = 'badge-danger';
    else if (level === 'medium') cls = 'badge-warning';

    return `<span class="verdict-badge ${cls}">${this.escapeHtml(label || level)}</span>`;
  },

  /**
   * Render Protocol Status Badge (SPF, DKIM, DMARC)
   */
  renderStatusBadge(status, securityLevel) {
    let cls = 'badge-info';
    if (securityLevel === 'success') cls = 'badge-success';
    else if (securityLevel === 'warning') cls = 'badge-warning';
    else if (securityLevel === 'danger') cls = 'badge-danger';

    return `<span class="card-badge ${cls}">${this.escapeHtml(status ? status.toUpperCase() : 'NONE')}</span>`;
  },

  /**
   * Render Network Hop Timeline
   */
  renderHopTimeline(network) {
    if (!network || !network.hops || network.hops.length === 0) {
      return `<div style="text-align: center; color: var(--text-muted); padding: 2rem;">No se detectaron cabeceras 'Received:' en este correo.</div>`;
    }

    const originGeo = network.originGeo || {};

    return `
      <div style="margin-bottom: 1.5rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; background: var(--bg-card); padding: 1.1rem 1.25rem; border-radius: 12px; border: 1px solid var(--border-color);">
        <div>
          <span style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Dirección IP de Origen Detectada:</span>
          <div style="display: flex; align-items: center; gap: 0.5rem; margin-top: 0.35rem; flex-wrap: wrap;">
            <span class="tag-ip" style="font-size: 1.05rem; padding: 0.3rem 0.8rem;">${this.escapeHtml(network.originIp)}</span>
            <span class="tag-origin">${network.isOriginPrivate ? 'IP Privada / LAN' : 'IP Pública de Internet'}</span>
            ${originGeo.country ? `
              <span class="tag-geo" title="${this.escapeHtml(originGeo.org || '')}">
                ${originGeo.flag || '🌐'} ${this.escapeHtml(originGeo.country)}
              </span>
              <span class="tag-rir">${this.escapeHtml(originGeo.rir || '')}</span>
            ` : ''}
            <button class="btn btn-primary btn-sm" onclick="App.geolocateIp('${this.escapeHtml(network.originIp)}')" style="padding: 0.3rem 0.75rem; font-size: 0.78rem;">
              🌍 Localizar Online / Ver Mapa
            </button>
          </div>
        </div>
        <div style="display: flex; gap: 1.5rem; align-items: center;">
          <div>
            <span style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Tiempo de tránsito:</span>
            <div style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-cyan); font-size: 1rem; margin-top: 0.25rem;">
              ${this.escapeHtml(network.totalTransitFormatted)}
            </div>
          </div>
          <div>
            <span style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Saltos Totales:</span>
            <div style="font-family: var(--font-mono); font-weight: 700; color: #fff; font-size: 1rem; margin-top: 0.25rem;">
              ${network.totalHops} relays
            </div>
          </div>
        </div>
      </div>

      <div class="hop-timeline">
        ${network.hops.map(hop => {
          const isOrigin = hop.hopNumber === network.originHopIndex;
          const geo = hop.geo || {};
          return `
            <div class="hop-item ${isOrigin ? 'is-origin' : ''}">
              <div class="hop-num">${hop.hopNumber}</div>
              <div class="hop-content">
                <div class="hop-title">
                  <span>${this.escapeHtml(hop.senderHost || 'Host emisor')}</span>
                  ${isOrigin ? `<span class="tag-origin">🎯 IP de Origen</span>` : ''}
                </div>
                ${hop.senderIp ? `
                  <div style="display: flex; align-items: center; gap: 0.45rem; margin-top: 0.35rem; flex-wrap: wrap;">
                    <span class="tag-ip">${this.escapeHtml(hop.senderIp)}</span>
                    ${geo.country ? `
                      <span class="tag-geo" title="${this.escapeHtml(geo.org || '')}">
                        ${geo.flag || '🌐'} ${this.escapeHtml(geo.country)}
                      </span>
                      <span class="tag-rir">${this.escapeHtml(geo.rir || '')}</span>
                    ` : ''}
                    <button class="btn-geo-sm" onclick="App.geolocateIp('${this.escapeHtml(hop.senderIp)}')" title="Localizar geográficamente esta IP">
                      🌍 Localizar
                    </button>
                  </div>
                ` : ''}
                <div class="hop-route" style="margin-top: 0.4rem;">
                  <span>Receptor: <strong>${this.escapeHtml(hop.receiverHost)}</strong></span> | 
                  <span>Protocolo: ${this.escapeHtml(hop.protocol)}</span>
                </div>
              </div>
              <div class="hop-delay">
                <span class="hop-delay-val">${this.escapeHtml(hop.delayFormatted)}</span>
                <span class="hop-time">${this.escapeHtml(hop.dateFormatted)}</span>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;
  },

  /**
   * Render Security Findings List
   */
  renderFindings(findings) {
    if (!findings || findings.length === 0) {
      return `
        <div style="text-align: center; color: #34d399; padding: 2.5rem; background: var(--risk-low-bg); border-radius: 12px; border: 1px solid var(--risk-low-border);">
          <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">🛡️</div>
          <h3 style="font-size: 1.1rem; margin-bottom: 0.25rem;">Excelente Perfil de Seguridad</h3>
          <p style="font-size: 0.85rem; color: var(--text-secondary);">No se detectaron anomalías críticas, discrepancias de remitente ni fallos de autenticación.</p>
        </div>
      `;
    }

    return `
      <div class="findings-list">
        ${findings.map(f => {
          let badgeCls = 'badge-warning';
          let borderCls = 'var(--risk-medium-border)';
          let bgCls = 'var(--risk-medium-bg)';
          let pointsColor = '#f59e0b';

          if (f.severity === 'critical') {
            badgeCls = 'badge-danger';
            borderCls = 'var(--risk-critical-border)';
            bgCls = 'var(--risk-critical-bg)';
            pointsColor = '#ef4444';
          } else if (f.severity === 'low') {
            badgeCls = 'badge-info';
            borderCls = 'rgba(59, 130, 246, 0.3)';
            bgCls = 'rgba(59, 130, 246, 0.1)';
            pointsColor = '#3b82f6';
          }

          return `
            <div class="finding-item" style="border-left: 4px solid ${pointsColor};">
              <div class="finding-points" style="background: ${bgCls}; border: 1px solid ${borderCls}; color: ${pointsColor};">
                +${f.points} pts
              </div>
              <div class="finding-body">
                <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
                  <span class="card-badge ${badgeCls}">${this.escapeHtml(f.protocol)}</span>
                  <h4 style="color: #fff; margin: 0;">${this.escapeHtml(f.title)}</h4>
                </div>
                <p>${this.escapeHtml(f.description)}</p>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;
  },

  /**
   * Render Attachments Table
   */
  renderAttachments(attachments) {
    if (!attachments || attachments.length === 0) {
      return `<div style="text-align: center; color: var(--text-muted); padding: 2rem;">Este correo no contiene archivos adjuntos.</div>`;
    }

    return `
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Nombre de Archivo</th>
              <th>Tipo MIME</th>
              <th>Tamaño</th>
              <th>Hash SHA-256</th>
              <th>Estado de Seguridad</th>
              <th>Acción</th>
            </tr>
          </thead>
          <tbody>
            ${attachments.map(att => {
              const sizeKb = (att.size / 1024).toFixed(1);
              return `
                <tr>
                  <td style="font-weight: 600; color: #fff;">
                    📁 ${this.escapeHtml(att.filename)}
                  </td>
                  <td style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-secondary);">
                    ${this.escapeHtml(att.contentType)}
                  </td>
                  <td style="font-family: var(--font-mono);">${sizeKb} KB</td>
                  <td style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--accent-cyan); max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${att.sha256}">
                    ${att.sha256}
                  </td>
                  <td>
                    ${att.isSuspicious ? 
                      `<span class="card-badge badge-danger">⚠️ EXTENSIÓN PELIGROSA</span>` : 
                      `<span class="card-badge badge-success">✓ Aceptable</span>`
                    }
                  </td>
                  <td>
                    ${att.dataBase64 ? `
                      <a href="data:${att.contentType};base64,${att.dataBase64}" download="${this.escapeHtml(att.filename)}" class="btn btn-secondary btn-sm" style="text-decoration: none;">
                        ⬇️ Descargar
                      </a>
                    ` : '<span style="color: var(--text-muted); font-size: 0.75rem;">No disponible</span>'}
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  },

  /**
   * Render History Rows
   */
  renderHistoryTable(rows, onSelectCallback) {
    if (!rows || rows.length === 0) {
      return `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No hay análisis registrados en el historial local.</td></tr>`;
    }

    return rows.map(r => {
      let riskBadgeCls = 'badge-success';
      if (r.risk_level === 'critical' || r.risk_level === 'high') riskBadgeCls = 'badge-danger';
      else if (r.risk_level === 'medium') riskBadgeCls = 'badge-warning';

      const dateStr = new Date(r.created_at).toLocaleString('es-ES', { dateStyle: 'short', timeStyle: 'short' });

      return `
        <tr style="cursor: pointer;" onclick="App.loadHistoryItem('${r.id}')">
          <td style="color: var(--text-muted); font-size: 0.78rem;">${dateStr}</td>
          <td style="font-weight: 600; color: #fff; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            ${this.escapeHtml(r.subject || '(Sin asunto)')}
          </td>
          <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            ${this.escapeHtml(r.sender)}
          </td>
          <td><span class="tag-ip">${this.escapeHtml(r.origin_ip)}</span></td>
          <td>
            <span class="card-badge ${riskBadgeCls}">${r.risk_score} pts (${r.risk_level.toUpperCase()})</span>
          </td>
          <td style="text-transform: uppercase; font-family: var(--font-mono); font-size: 0.75rem;">
            .${this.escapeHtml(r.file_type)}
          </td>
          <td onclick="event.stopPropagation();">
            <button class="btn btn-secondary btn-sm" onclick="App.deleteHistoryItem('${r.id}')" title="Eliminar" style="color: #ef4444; border-color: rgba(239, 68, 68, 0.3);">
              🗑️
            </button>
          </td>
        </tr>
      `;
    }).join('');
  },

  /**
   * Sanitize HTML to prevent XSS / Script Execution
   * Strips <script>, <object>, <embed>, <iframe>, event attributes, javascript: URIs.
   */
  sanitizeHtml(dirtyHtml) {
    if (!dirtyHtml) return '';
    let sanitized = dirtyHtml
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
      .replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '')
      .replace(/<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi, '')
      .replace(/\bon\w+\s*=\s*(?:'[^']*'|"[^"]*"|[^\s>]+)/gi, '')
      .replace(/href\s*=\s*['"]?javascript:[^'"]*['"]?/gi, 'href="#"');

    return sanitized;
  },

  escapeHtml(str) {
    if (!str && str !== 0) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  },

  /**
   * Render Geolocation Modal Content
   */
  renderGeoModalContent(data) {
    if (!data) return '<div style="color: var(--text-muted); padding: 1.5rem; text-align: center;">Sin datos de geolocalización.</div>';
    
    const isOnline = data.source === 'online_api';
    const isPrivate = data.source === 'offline_private';
    
    return `
      <div style="margin-bottom: 1.25rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.75rem; background: #060910; padding: 0.85rem 1rem; border-radius: 10px; border: 1px solid var(--border-color);">
        <div style="display: flex; align-items: center; gap: 0.65rem;">
          <span style="font-size: 2rem;">${data.flag || '🌐'}</span>
          <div>
            <div style="font-weight: 700; color: #fff; font-size: 1.05rem;">${this.escapeHtml(data.country || 'Desconocido')}</div>
            <div style="font-size: 0.78rem; color: var(--accent-cyan); font-family: var(--font-mono);">${this.escapeHtml(data.ip)}</div>
          </div>
        </div>
        <div>
          ${isOnline ? '<span class="badge badge-success">✓ Consulta Online Exitosa</span>' : (isPrivate ? '<span class="badge badge-info">🏠 Red Local (Privada)</span>' : '<span class="badge badge-warning">🌐 Base de Datos RIR Offline</span>')}
        </div>
      </div>

      <div class="geo-grid">
        <div class="geo-field">
          <span class="geo-field-lbl">Ciudad / Localidad</span>
          <span class="geo-field-val">${this.escapeHtml(data.city || 'No disponible')}</span>
        </div>
        <div class="geo-field">
          <span class="geo-field-lbl">Región / Estado</span>
          <span class="geo-field-val">${this.escapeHtml(data.region || 'No especificada')}</span>
        </div>
        <div class="geo-field">
          <span class="geo-field-lbl">Proveedor ISP</span>
          <span class="geo-field-val">${this.escapeHtml(data.isp || 'No identificado')}</span>
        </div>
        <div class="geo-field">
          <span class="geo-field-lbl">Organización / Cloud</span>
          <span class="geo-field-val">${this.escapeHtml(data.org || 'No especificada')}</span>
        </div>
        <div class="geo-field">
          <span class="geo-field-lbl">Sistema Autónomo (ASN / RIR)</span>
          <span class="geo-field-val" style="font-family: var(--font-mono);">${this.escapeHtml(data.asn || 'N/A')}</span>
        </div>
        <div class="geo-field">
          <span class="geo-field-lbl">Coordenadas Geográficas</span>
          <span class="geo-field-val" style="font-family: var(--font-mono);">${data.lat && data.lon ? `${data.lat}, ${data.lon}` : 'No disponibles (RIR regional)'}</span>
        </div>
      </div>

      <div class="geo-actions">
        ${data.mapsUrl ? `
          <a href="${data.mapsUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-primary btn-sm" style="text-decoration: none;">
            🗺️ Abrir en Google Maps
          </a>
        ` : ''}
        ${data.virustotalUrl ? `
          <a href="${data.virustotalUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary btn-sm" style="text-decoration: none;">
            🛡️ Reputación VirusTotal
          </a>
        ` : ''}
        ${data.abuseipdbUrl ? `
          <a href="${data.abuseipdbUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary btn-sm" style="text-decoration: none;">
            ⚠️ Reportes AbuseIPDB
          </a>
        ` : ''}
      </div>
      <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.85rem;">
        * Nota: Las consultas online se realizan bajo demanda del perito informático forense para proteger la privacidad del entorno local.
      </div>
    `;
  },

  /**
   * Generates a complete, self-contained, printable HTML forensic report
   */
  generateHtmlReport(data) {
    const dateFormatted = new Date().toLocaleString('es-ES', { dateStyle: 'full', timeStyle: 'medium' });
    const emailDate = data.email?.date || 'No especificada';
    const riskScore = data.risk?.score || 0;
    const riskLevel = (data.risk?.level || 'low').toUpperCase();
    const riskColor = data.risk?.color || '#10b981';
    const riskLabel = data.risk?.label || 'Bajo Riesgo';
    const attachments = data.email?.attachments || [];
    const hops = data.network?.hops || [];
    const findings = data.risk?.findings || [];
    const badgeSrc = window.FORENSIC_BADGE_B64 || 'img/logo_forense.jpg';

    return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Informe Forense - ForensicBuzMail - ${this.escapeHtml(data.filename)}</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1f293d;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --accent: #3b82f6;
      --cyan: #06b6d4;
    }
    @media print {
      body { background: #fff !important; color: #000 !important; }
      .no-print { display: none !important; }
      .card { border: 1px solid #ccc !important; background: #fff !important; color: #000 !important; box-shadow: none !important; }
      .report-header { border-bottom: 2px solid #000 !important; }
      th { background: #eee !important; color: #000 !important; }
      td { border-bottom: 1px solid #ddd !important; color: #000 !important; }
      pre { background: #f8fafc !important; color: #000 !important; border: 1px solid #ccc !important; }
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 2.5rem 1.5rem;
      max-width: 1100px;
      margin: 0 auto;
    }
    .toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
    }
    .btn {
      background: var(--accent);
      color: #fff;
      border: none;
      padding: 0.6rem 1.25rem;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
      font-size: 0.88rem;
    }
    .report-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      padding-bottom: 1.5rem;
      border-bottom: 1px solid var(--border);
      flex-wrap: wrap;
      gap: 1.5rem;
    }
    .brand h1 { font-size: 1.6rem; margin: 0; color: #fff; }
    .brand span { font-size: 0.85rem; color: var(--cyan); text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em; }
    .meta-box { text-align: right; font-size: 0.82rem; color: var(--text-muted); }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 1.75rem;
    }
    .card-title {
      font-size: 1.1rem;
      font-weight: 700;
      margin-bottom: 1rem;
      color: #fff;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.5rem;
    }
    .verdict-box {
      display: grid;
      grid-template-columns: 180px 1fr;
      gap: 1.5rem;
      align-items: center;
    }
    .score-circle {
      width: 130px;
      height: 130px;
      border-radius: 50%;
      border: 6px solid ${riskColor};
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      margin: 0 auto;
    }
    .score-num { font-size: 2.5rem; font-weight: 800; line-height: 1; font-family: monospace; }
    .score-sub { font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); }
    .badge {
      display: inline-block;
      padding: 0.25rem 0.65rem;
      border-radius: 6px;
      font-weight: 700;
      font-size: 0.76rem;
      text-transform: uppercase;
    }
    .badge-success { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
    .badge-danger { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .badge-warning { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
    table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; font-size: 0.85rem; }
    th { text-align: left; padding: 0.65rem 0.75rem; background: rgba(255,255,255,0.03); color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; }
    td { padding: 0.65rem 0.75rem; border-bottom: 1px solid var(--border); }
    .prop-row { display: flex; justify-content: space-between; padding: 0.45rem 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 0.85rem; }
    .prop-k { color: var(--text-muted); width: 220px; font-weight: 500; }
    .prop-v { font-weight: 600; color: #fff; word-break: break-all; flex: 1; }
    pre {
      background: #050811;
      border: 1px solid var(--border);
      padding: 1rem;
      border-radius: 8px;
      font-family: monospace;
      font-size: 0.8rem;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
      color: #93c5fd;
    }
  </style>
</head>
<body>

  <div class="toolbar no-print">
    <div>
      <span style="font-size: 0.88rem; color: var(--text-muted);">Informe generado por <strong>ForensicBuzMail</strong> · Policía Científica</span>
    </div>
    <button class="btn" onclick="window.print()">🖨️ Imprimir / Guardar en PDF</button>
  </div>

  <div class="report-header">
    <div style="display: flex; align-items: center; gap: 1.25rem;">
      <img src="${badgeSrc}" style="width: 76px; height: 76px; object-fit: contain; filter: drop-shadow(0 4px 6px rgba(0,0,0,0.5));" alt="Policía Científica">
      <div class="brand">
        <div style="font-size: 0.78rem; font-weight: 800; letter-spacing: 0.08em; color: #f59e0b; text-transform: uppercase;">POLICÍA NACIONAL · POLICÍA CIENTÍFICA</div>
        <div style="font-size: 0.74rem; color: #94a3b8; font-weight: 600;">Brigada Provincial de Madrid · Informática Forense</div>
        <h1 style="font-size: 1.5rem; margin-top: 0.2rem; color: #fff;">ForensicBuzMail</h1>
        <span style="font-size: 0.8rem; color: var(--cyan);">Dictamen Pericial de Análisis de Correo Electrónico</span>
      </div>
    </div>
    <div class="meta-box">
      <div><strong>Fecha de Auditoría:</strong> ${dateFormatted}</div>
      <div><strong>Archivo de Evidencia:</strong> ${this.escapeHtml(data.filename)} (${(data.fileSize / 1024).toFixed(1)} KB)</div>
      <div><strong>Identificador Pericial:</strong> <code>${data.id}</code></div>
      <div><strong>Entorno:</strong> 100% Local y Aislado</div>
    </div>
  </div>

  <!-- VEREDICTO DE RIESGO -->
  <div class="card">
    <div class="card-title">🛡️ Resumen Ejecutivo & Evaluación de Amenaza</div>
    <div class="verdict-box">
      <div class="score-circle">
        <span class="score-num" style="color: ${riskColor};">${riskScore}</span>
        <span class="score-sub">Riesgo / 100</span>
      </div>
      <div>
        <div style="margin-bottom: 0.5rem;">
          <span class="badge" style="background: ${riskColor}33; color: ${riskColor}; border: 1px solid ${riskColor}; font-size: 0.95rem; padding: 0.35rem 0.9rem;">
            ${this.escapeHtml(riskLabel)}
          </span>
        </div>
        <p style="font-size: 0.92rem; color: #cbd5e1; margin-bottom: 0.5rem;">
          <strong>Veredicto Pericial:</strong> Este correo ha sido evaluado con un nivel de riesgo <strong>${riskLevel}</strong> (${riskScore}/100 puntos forenses).
        </p>
        <div style="font-size: 0.84rem; color: var(--text-muted);">
          ${this.escapeHtml(data.risk?.recommendations || 'Se aconseja extremar precauciones.')}
        </div>
      </div>
    </div>
  </div>

  <!-- IDENTIFICADORES GENERALES -->
  <div class="card">
    <div class="card-title">✉️ Identificadores del Mensaje</div>
    <div class="prop-row"><span class="prop-k">Asunto (Subject):</span><span class="prop-v">${this.escapeHtml(data.email?.subject || '(Sin Asunto)')}</span></div>
    <div class="prop-row"><span class="prop-k">Remitente Visible (From):</span><span class="prop-v">${this.escapeHtml(data.email?.from?.full || data.email?.from?.address || 'Desconocido')}</span></div>
    <div class="prop-row"><span class="prop-k">Destinatario (To):</span><span class="prop-v">${this.escapeHtml((data.email?.to || []).map(t => t.full || t.address).join(', ') || 'Desconocido')}</span></div>
    <div class="prop-row"><span class="prop-k">Fecha del Mensaje (Date):</span><span class="prop-v">${this.escapeHtml(emailDate)}</span></div>
    <div class="prop-row"><span class="prop-k">Envelope Sender (Return-Path):</span><span class="prop-v">${this.escapeHtml(data.email?.returnPath || 'No especificado')}</span></div>
    <div class="prop-row"><span class="prop-k">Dirección de Respuesta (Reply-To):</span><span class="prop-v">${this.escapeHtml(data.email?.replyTo?.address || 'No especificada')}</span></div>
    <div class="prop-row"><span class="prop-k">Message-ID:</span><span class="prop-v" style="font-family: monospace;">${this.escapeHtml(data.email?.messageId || 'No asignado')}</span></div>
    <div class="prop-row"><span class="prop-k">IP Pública de Origen:</span><span class="prop-v" style="color: var(--cyan); font-family: monospace;">${this.escapeHtml(data.network?.originIp || 'No detectada')} ${data.network?.originGeo ? `[${data.network.originGeo.flag || ''} ${data.network.originGeo.country || ''} · ${data.network.originGeo.rir || ''}]` : ''} (${data.network?.isOriginPrivate ? 'IP Privada' : 'IP Pública de Internet'})</span></div>
  </div>

  <!-- PROTOCOLOS DE SEGURIDAD -->
  <div class="card">
    <div class="card-title">🔐 Auditoría de Protocolos de Autenticación</div>
    <table>
      <thead>
        <tr>
          <th>Protocolo</th>
          <th>Estado</th>
          <th>Alineación de Dominio</th>
          <th>Detalles Técnicos</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>SPF (RFC 7208)</strong></td>
          <td><span class="badge ${data.spf?.securityLevel === 'success' ? 'badge-success' : (data.spf?.securityLevel === 'danger' ? 'badge-danger' : 'badge-warning')}">${this.escapeHtml((data.spf?.status || 'none').toUpperCase())}</span></td>
          <td>${data.spf?.isAligned ? '<span class="badge badge-success">✓ Alineado</span>' : '<span class="badge badge-danger">✗ Desalineado</span>'}</td>
          <td>${this.escapeHtml(data.spf?.summaryText || '')}<br><small style="color: var(--text-muted);">IP Emisora: ${this.escapeHtml(data.spf?.clientIp || '')} | Envelope: ${this.escapeHtml(data.spf?.sender || '')}</small></td>
        </tr>
        <tr>
          <td><strong>DKIM (RFC 6376)</strong></td>
          <td><span class="badge ${data.dkim?.securityLevel === 'success' ? 'badge-success' : (data.dkim?.securityLevel === 'danger' ? 'badge-danger' : 'badge-warning')}">${this.escapeHtml((data.dkim?.status || 'none').toUpperCase())}</span></td>
          <td>${data.dkim?.hasAlignedSignature ? '<span class="badge badge-success">✓ Alineado</span>' : '<span class="badge badge-danger">✗ Desalineado</span>'}</td>
          <td>${this.escapeHtml(data.dkim?.summaryText || '')}<br><small style="color: var(--text-muted);">${data.dkim?.signaturesCount || 0} firma(s) digital(es) detectada(s)</small></td>
        </tr>
        <tr>
          <td><strong>DMARC (RFC 7489)</strong></td>
          <td><span class="badge ${data.dmarc?.securityLevel === 'success' ? 'badge-success' : 'badge-danger'}">${this.escapeHtml((data.dmarc?.status || 'none').toUpperCase())}</span></td>
          <td>${data.dmarc?.status === 'pass' ? '<span class="badge badge-success">✓ Aprobado</span>' : '<span class="badge badge-danger">✗ Fallido</span>'}</td>
          <td>${this.escapeHtml(data.dmarc?.summaryText || '')}<br><small style="color: var(--text-muted);">Política: ${this.escapeHtml((data.dmarc?.policy || 'none').toUpperCase())}</small></td>
        </tr>
      </tbody>
    </table>
  </div>

  <!-- RUTA DE SALTOS SMTP -->
  <div class="card">
    <div class="card-title">🌐 Trazabilidad de Red (Cadena de Servidores SMTP Relays)</div>
    <table>
      <thead>
        <tr>
          <th>Salto #</th>
          <th>Servidor Emisor</th>
          <th>IP Registrada</th>
          <th>Localización (RIR / Región)</th>
          <th>Servidor Receptor</th>
          <th>Protocolo</th>
          <th>Marca de Tiempo</th>
        </tr>
      </thead>
      <tbody>
        ${hops.map(h => `
          <tr ${h.hopNumber === data.network?.originHopIndex ? 'style="background: rgba(245, 158, 11, 0.1);"' : ''}>
            <td><strong>#${h.hopNumber}</strong> ${h.hopNumber === data.network?.originHopIndex ? '🎯 (Origen)' : ''}</td>
            <td>${this.escapeHtml(h.senderHost || 'Desconocido')}</td>
            <td><code>${this.escapeHtml(h.senderIp || 'N/A')}</code></td>
            <td>${h.geo ? `<span style="font-size: 0.8rem;">${h.geo.flag || '🌐'} ${this.escapeHtml(h.geo.country || '')} <small style="color: var(--text-muted);">(${this.escapeHtml(h.geo.rir || '')})</small></span>` : '<span style="color: var(--text-muted); font-size: 0.8rem;">Local / LAN</span>'}</td>
            <td>${this.escapeHtml(h.receiverHost || 'Desconocido')}</td>
            <td>${this.escapeHtml(h.protocol || 'SMTP')}</td>
            <td>${this.escapeHtml(h.dateFormatted || '')}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>

  <!-- VECTORES DE AMENAZA -->
  <div class="card">
    <div class="card-title">⚠️ Indicadores de Riesgo Detectados</div>
    ${findings.length === 0 ? '<div style="color: #34d399; padding: 1rem;">No se detectaron anomalías ni factores de riesgo.</div>' : `
      <table>
        <thead>
          <tr>
            <th>Gravedad</th>
            <th>Puntos</th>
            <th>Protocolo</th>
            <th>Hallazgo Forense</th>
            <th>Descripción</th>
          </tr>
        </thead>
        <tbody>
          ${findings.map(f => `
            <tr>
              <td><span class="badge ${f.severity === 'critical' ? 'badge-danger' : (f.severity === 'high' ? 'badge-danger' : 'badge-warning')}">${f.severity.toUpperCase()}</span></td>
              <td><strong>+${f.points}</strong></td>
              <td>${this.escapeHtml(f.protocol)}</td>
              <td><strong>${this.escapeHtml(f.title)}</strong></td>
              <td style="color: var(--text-muted);">${this.escapeHtml(f.description)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `}
  </div>

  <!-- ADJUNTOS -->
  <div class="card">
    <div class="card-title">📎 Archivos Adjuntos Extraídos (${attachments.length})</div>
    ${attachments.length === 0 ? '<div style="color: var(--text-muted); padding: 1rem;">Este mensaje no contiene archivos adjuntos.</div>' : `
      <table>
        <thead>
          <tr>
            <th>Nombre</th>
            <th>Tipo MIME</th>
            <th>Tamaño</th>
            <th>Hash SHA-256</th>
            <th>Alerta de Riesgo</th>
          </tr>
        </thead>
        <tbody>
          ${attachments.map(a => `
            <tr>
              <td><strong>${this.escapeHtml(a.filename)}</strong></td>
              <td><code>${this.escapeHtml(a.contentType)}</code></td>
              <td>${(a.size / 1024).toFixed(1)} KB</td>
              <td><code style="font-size: 0.72rem;">${a.sha256}</code></td>
              <td>${a.isSuspicious ? '<span class="badge badge-danger">⚠️ EXTENSIÓN PELIGROSA</span>' : '<span class="badge badge-success">✓ Aceptable</span>'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `}
  </div>

  <!-- CABECERAS RAW -->
  <div class="card">
    <div class="card-title">📜 Cabeceras de Red Originales (RFC 5322 Verbatim)</div>
    <pre>${this.escapeHtml(data.email?.rawHeadersText || '')}</pre>
  </div>

</body>
</html>`;
  }
};

