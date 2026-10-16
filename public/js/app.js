/**
 * Email Forensics & Security Analyzer - Application Controller
 */
const App = {
  currentAnalysis: null,
  activeTab: 'tab-overview',

  init() {
    this.bindEvents();
    this.loadHistory();
    this.loadSamples();
    this.preloadLogo();
  },

  async preloadLogo() {
    try {
      const res = await fetch('/img/logo_base64.txt');
      if (res.ok) {
        const text = await res.text();
        window.FORENSIC_BADGE_B64 = 'data:image/jpeg;base64,' + text.trim();
      }
    } catch (e) {
      console.warn('Logo preloading fallback:', e);
    }
  },

  bindEvents() {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');

    if (dropzone && fileInput) {
      dropzone.addEventListener('click', () => fileInput.click());

      dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
      });

      dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('dragover');
      });

      dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          this.handleFileUpload(e.dataTransfer.files[0]);
        }
      });

      fileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files.length > 0) {
          this.handleFileUpload(e.target.files[0]);
        }
      });
    }

    // Tabs
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const target = e.currentTarget.getAttribute('data-tab');
        this.switchTab(target);
      });
    });

    // Header filter
    const headerSearch = document.getElementById('header-search');
    if (headerSearch) {
      headerSearch.addEventListener('input', (e) => {
        this.filterHeaders(e.target.value);
      });
    }

    // History search
    const historySearch = document.getElementById('history-search');
    if (historySearch) {
      historySearch.addEventListener('input', (e) => {
        this.loadHistory(e.target.value);
      });
    }
  },

  switchTab(tabId) {
    this.activeTab = tabId;
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
    });
    document.querySelectorAll('.tab-pane').forEach(pane => {
      pane.classList.toggle('active', pane.id === tabId);
    });
  },

  async handleFileUpload(file) {
    const ext = file.name.slice(file.name.lastIndexOf('.')).toLowerCase();
    if (ext !== '.eml' && ext !== '.msg') {
      this.showToast('Formato no soportado. Por favor arrastre un archivo .eml o .msg.', 'error');
      return;
    }

    this.showLoading(true);
    this.showToast(`Analizando ${file.name}...`, 'info');

    try {
      const arrayBuffer = await file.arrayBuffer();
      const base64Data = this.arrayBufferToBase64(arrayBuffer);

      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filename: file.name,
          base64: base64Data
        })
      });

      const result = await response.json();
      if (result.success) {
        this.renderAnalysis(result.data);
        this.showToast('¡Análisis forense completado!', 'success');
        this.loadHistory(); // Refresh history
      } else {
        this.showToast(`Error al procesar: ${result.error}`, 'error');
      }
    } catch (err) {
      this.showToast(`Fallo en el análisis: ${err.message}`, 'error');
    } finally {
      this.showLoading(false);
    }
  },

  async loadSample(sampleName) {
    this.showLoading(true);
    this.showToast(`Cargando muestra forense: ${sampleName}...`, 'info');

    try {
      const response = await fetch(`/api/samples/${encodeURIComponent(sampleName)}`, {
        method: 'POST'
      });
      const result = await response.json();
      if (result.success) {
        this.renderAnalysis(result.data);
        this.showToast('Muestra cargada y analizada con éxito.', 'success');
        this.loadHistory();
      } else {
        this.showToast(`Error al cargar muestra: ${result.error}`, 'error');
      }
    } catch (err) {
      this.showToast(`Error de conexión local: ${err.message}`, 'error');
    } finally {
      this.showLoading(false);
    }
  },

  async loadSamples() {
    try {
      const res = await fetch('/api/samples');
      const json = await res.json();
      if (json.success && json.data.length > 0) {
        const container = document.getElementById('samples-container');
        if (container) {
          container.innerHTML = `
            <span>Muestras forenses rápidas:</span>
            ${json.data.map(s => `
              <button class="sample-chip" onclick="App.loadSample('${s.name}')">
                ⚡ ${s.name}
              </button>
            `).join('')}
          `;
        }
      }
    } catch (e) {
      console.warn('No se pudieron listar muestras:', e);
    }
  },

  async loadHistory(query = '') {
    try {
      const res = await fetch(`/api/history?q=${encodeURIComponent(query)}`);
      const json = await res.json();
      if (json.success) {
        const tbody = document.getElementById('history-tbody');
        if (tbody) {
          tbody.innerHTML = Components.renderHistoryTable(json.data);
        }
      }
    } catch (e) {
      console.warn('Error cargando historial:', e);
    }
  },

  async loadHistoryItem(id) {
    this.showLoading(true);
    try {
      const res = await fetch(`/api/history/${id}`);
      const json = await res.json();
      if (json.success) {
        this.renderAnalysis(json.data);
        this.switchTab('tab-overview');
        this.showToast('Registro forense cargado desde el historial.', 'info');
      }
    } catch (e) {
      this.showToast('Error cargando registro', 'error');
    } finally {
      this.showLoading(false);
    }
  },

  async deleteHistoryItem(id) {
    if (!confirm('¿Confirma eliminar este registro del historial local?')) return;
    try {
      const res = await fetch(`/api/history/${id}`, { method: 'DELETE' });
      const json = await res.json();
      if (json.success) {
        this.showToast('Registro eliminado.', 'info');
        this.loadHistory();
      }
    } catch (e) {
      this.showToast('Error al eliminar', 'error');
    }
  },

  renderAnalysis(data) {
    this.currentAnalysis = data;
    const viewSection = document.getElementById('analysis-results');
    if (viewSection) viewSection.style.display = 'block';

    // 1. VERDICT HERO GAUGE
    const scoreVal = document.getElementById('hero-score-val');
    const scoreCircle = document.getElementById('hero-score-circle');
    const riskBadgeContainer = document.getElementById('hero-risk-badge');
    const subjectEl = document.getElementById('hero-subject');
    const filenameEl = document.getElementById('hero-filename');
    const fromEl = document.getElementById('hero-from');
    const toEl = document.getElementById('hero-to');
    const dateEl = document.getElementById('hero-date');
    const originIpEl = document.getElementById('hero-origin-ip');

    if (scoreVal) scoreVal.textContent = data.risk.score;
    if (scoreCircle) {
      scoreCircle.style.borderColor = data.risk.color;
      scoreCircle.style.boxShadow = `0 0 20px ${data.risk.color}33`;
    }
    if (riskBadgeContainer) {
      riskBadgeContainer.innerHTML = Components.renderRiskBadge(data.risk.level, data.risk.label);
    }

    if (subjectEl) subjectEl.textContent = data.email.subject || '(Sin asunto)';
    if (filenameEl) filenameEl.textContent = `${data.filename} (${(data.fileSize / 1024).toFixed(1)} KB)`;
    if (fromEl) fromEl.textContent = data.email.from.full || data.email.from.address || 'Desconocido';
    if (toEl) toEl.textContent = (data.email.to || []).map(t => t.full || t.address).join(', ') || 'Desconocido';
    if (dateEl) dateEl.textContent = data.email.date || 'No especificada';
    if (originIpEl) {
      const geo = data.network.originGeo || {};
      originIpEl.innerHTML = `
        <div style="display: flex; align-items: center; gap: 0.45rem; flex-wrap: wrap; margin-top: 0.2rem;">
          <span class="tag-ip" style="font-size: 0.92rem;">${Components.escapeHtml(data.network.originIp)}</span>
          ${geo.country ? `
            <span class="tag-geo" title="${Components.escapeHtml(geo.org || '')}">
              ${geo.flag || '🌐'} ${Components.escapeHtml(geo.country)}
            </span>
            <span class="tag-rir">${Components.escapeHtml(geo.rir || '')}</span>
          ` : ''}
          <button class="btn-geo-sm" onclick="App.geolocateIp('${Components.escapeHtml(data.network.originIp)}')" style="margin-left: 0.25rem;">
            🌍 Localizar
          </button>
        </div>
      `;
    }

    const quickIpInput = document.getElementById('quick-ip-input');
    if (quickIpInput && data.network.originIp && data.network.originIp !== 'No detectada') {
      quickIpInput.value = data.network.originIp;
    }

    // Mini pills in sidebar
    const spfPill = document.getElementById('pill-spf');
    const dkimPill = document.getElementById('pill-dkim');
    const dmarcPill = document.getElementById('pill-dmarc');

    if (spfPill) spfPill.innerHTML = `<span>SPF</span> ${Components.renderStatusBadge(data.spf.status, data.spf.securityLevel)}`;
    if (dkimPill) dkimPill.innerHTML = `<span>DKIM</span> ${Components.renderStatusBadge(data.dkim.status, data.dkim.securityLevel)}`;
    if (dmarcPill) dmarcPill.innerHTML = `<span>DMARC</span> ${Components.renderStatusBadge(data.dmarc.status, data.dmarc.securityLevel)}`;

    // 2. PROTOCOL CARDS (SPF, DKIM, DMARC)
    this.renderProtocolCards(data);

    // 3. NETWORK ROUTE (SMTP Hops)
    const hopsContainer = document.getElementById('hops-container');
    if (hopsContainer) {
      hopsContainer.innerHTML = Components.renderHopTimeline(data.network);
    }

    // 4. RISK FINDINGS
    const findingsContainer = document.getElementById('findings-container');
    if (findingsContainer) {
      findingsContainer.innerHTML = Components.renderFindings(data.risk.findings);
    }

    // 5. ATTACHMENTS
    const attContainer = document.getElementById('attachments-container');
    const attTabCount = document.getElementById('att-tab-count');
    if (attContainer) {
      attContainer.innerHTML = Components.renderAttachments(data.email.attachments);
    }
    if (attTabCount) {
      attTabCount.textContent = (data.email.attachments && data.email.attachments.length > 0) ? `(${data.email.attachments.length})` : '';
    }

    // 6. CONTENT PREVIEW
    this.renderEmailBody(data.email);

    // 7. RAW HEADERS
    const rawHeadersBox = document.getElementById('raw-headers-box');
    if (rawHeadersBox) {
      rawHeadersBox.textContent = data.email.rawHeadersText || 'No hay cabeceras raw disponibles.';
    }

    // Scroll to results smoothly
    viewSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  },

  renderProtocolCards(data) {
    // SPF Card
    const spfCard = document.getElementById('card-spf-content');
    if (spfCard) {
      spfCard.innerHTML = `
        <div class="protocol-detail-row">
          <span class="k">Estado SPF:</span>
          <span class="v">${Components.renderStatusBadge(data.spf.status, data.spf.securityLevel)}</span>
        </div>
        <div class="protocol-detail-row">
          <span class="k">IP Emisora:</span>
          <span class="v">${Components.escapeHtml(data.spf.clientIp)}</span>
        </div>
        <div class="protocol-detail-row">
          <span class="k">Envelope Sender:</span>
          <span class="v">${Components.escapeHtml(data.spf.sender)}</span>
        </div>
        <div class="protocol-detail-row">
          <span class="k">Dominio SPF:</span>
          <span class="v">${Components.escapeHtml(data.spf.spfDomain)}</span>
        </div>
        <div class="protocol-detail-row">
          <span class="k">Alineación con From:</span>
          <span class="v">${data.spf.isAligned ? '<span class="badge-success card-badge">✓ ALINEADO (' + data.spf.alignmentType.toUpperCase() + ')</span>' : '<span class="badge-danger card-badge">✗ NO ALINEADO</span>'}</span>
        </div>
        <div class="protocol-explanation">${Components.escapeHtml(data.spf.summaryText)}</div>
      `;
    }

    // DKIM Card
    const dkimCard = document.getElementById('card-dkim-content');
    if (dkimCard) {
      const primarySig = (data.dkim.signatures && data.dkim.signatures.length > 0) ? data.dkim.signatures[0] : null;
      dkimCard.innerHTML = `
        <div class="protocol-detail-row">
          <span class="k">Estado DKIM:</span>
          <span class="v">${Components.renderStatusBadge(data.dkim.status, data.dkim.securityLevel)}</span>
        </div>
        <div class="protocol-detail-row">
          <span class="k">Firmas Presentes:</span>
          <span class="v">${data.dkim.signaturesCount} firma(s)</span>
        </div>
        <div class="protocol-detail-row">
          <span class="k">Dominio Firmante (d=):</span>
          <span class="v">${primarySig ? Components.escapeHtml(primarySig.domain) : 'Ninguno'}</span>
        </div>
        <div class="protocol-detail-row">
          <span class="k">Selector (s=):</span>
          <span class="v">${primarySig ? Components.escapeHtml(primarySig.selector) : 'N/A'}</span>
        </div>
        <div class="protocol-detail-row">
          <span class="k">Algoritmo (a=):</span>
          <span class="v">${primarySig ? Components.escapeHtml(primarySig.algorithm) : 'N/A'}</span>
        </div>
        <div class="protocol-detail-row">
          <span class="k">Alineación con From:</span>
          <span class="v">${data.dkim.hasAlignedSignature ? '<span class="badge-success card-badge">✓ ALINEADO</span>' : '<span class="badge-danger card-badge">✗ NO ALINEADO</span>'}</span>
        </div>
        <div class="protocol-explanation">${Components.escapeHtml(data.dkim.summaryText)}</div>
      `;
    }

    // DMARC Card
    const dmarcCard = document.getElementById('card-dmarc-content');
    if (dmarcCard) {
      dmarcCard.innerHTML = `
        <div class="protocol-detail-row">
          <span class="k">Veredicto DMARC:</span>
          <span class="v">${Components.renderStatusBadge(data.dmarc.status, data.dmarc.securityLevel)}</span>
        </div>
        <div class="protocol-detail-row">
          <span class="k">Política Declarada:</span>
          <span class="v" style="color: var(--accent-cyan); text-transform: uppercase;">${Components.escapeHtml(data.dmarc.policy)}</span>
        </div>
        <div class="protocol-detail-row">
          <span class="k">SPF DMARC Pass:</span>
          <span class="v">${data.dmarc.spfDmarcPass ? '<span class="badge-success card-badge">✓ SÍ</span>' : '<span class="badge-danger card-badge">✗ NO</span>'}</span>
        </div>
        <div class="protocol-detail-row">
          <span class="k">DKIM DMARC Pass:</span>
          <span class="v">${data.dmarc.dkimDmarcPass ? '<span class="badge-success card-badge">✓ SÍ</span>' : '<span class="badge-danger card-badge">✗ NO</span>'}</span>
        </div>
        <div class="protocol-explanation">
          <strong>${Components.escapeHtml(data.dmarc.summaryText)}</strong>
          <div style="margin-top: 0.5rem; font-size: 0.76rem; color: var(--text-muted);">${Components.escapeHtml(data.dmarc.policyExplanation)}</div>
        </div>
      `;
    }
  },

  renderEmailBody(email) {
    const iframe = document.getElementById('email-html-frame');
    const textPreview = document.getElementById('email-text-box');
    const htmlTabBtn = document.getElementById('btn-view-html');
    const textTabBtn = document.getElementById('btn-view-text');

    if (textPreview) {
      textPreview.textContent = email.textBody || '(El mensaje no contiene cuerpo de texto plano)';
    }

    if (iframe) {
      if (email.htmlBody) {
        // Sanitize and inject into sandboxed iframe
        const clean = Components.sanitizeHtml(email.htmlBody);
        const doc = iframe.contentWindow?.document || iframe.contentDocument;
        if (doc) {
          doc.open();
          doc.write(`
            <!DOCTYPE html>
            <html>
              <head>
                <meta charset="utf-8">
                <style>
                  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 1.5rem; color: #1e293b; line-height: 1.6; word-break: break-word; }
                  img { max-width: 100%; height: auto; }
                  a { color: #2563eb; }
                </style>
              </head>
              <body>${clean}</body>
            </html>
          `);
          doc.close();
        }
      } else {
        const doc = iframe.contentWindow?.document || iframe.contentDocument;
        if (doc) {
          doc.open();
          doc.write('<body style="font-family:sans-serif;color:#64748b;padding:2rem;text-align:center;">(Este correo no tiene versión en formato HTML)</body>');
          doc.close();
        }
      }
    }
  },

  filterHeaders(query) {
    const box = document.getElementById('raw-headers-box');
    if (!box || !this.currentAnalysis) return;
    const raw = this.currentAnalysis.email.rawHeadersText || '';
    if (!query || query.trim() === '') {
      box.textContent = raw;
      return;
    }
    const lines = raw.split(/\r?\n/);
    const q = query.toLowerCase();
    const matched = lines.filter(l => l.toLowerCase().includes(q));
    box.textContent = matched.join('\n') || `(Sin coincidencias para "${query}")`;
  },

  copyHeaders() {
    if (!this.currentAnalysis) return;
    const text = this.currentAnalysis.email.rawHeadersText || '';
    navigator.clipboard.writeText(text).then(() => {
      this.showToast('Cabeceras copiadas al portapapeles.', 'success');
    }).catch(() => {
      this.showToast('No se pudo copiar automáticamente', 'error');
    });
  },

  setInputMode(mode) {
    const btnFile = document.getElementById('btn-mode-file');
    const btnText = document.getElementById('btn-mode-text');
    const dropzone = document.getElementById('dropzone');
    const rawPanel = document.getElementById('raw-text-panel');

    if (mode === 'text') {
      if (btnFile) btnFile.classList.remove('active');
      if (btnText) btnText.classList.add('active');
      if (dropzone) dropzone.style.display = 'none';
      if (rawPanel) {
        rawPanel.style.display = 'block';
        rawPanel.classList.add('active');
      }
    } else {
      if (btnFile) btnFile.classList.add('active');
      if (btnText) btnText.classList.remove('active');
      if (dropzone) dropzone.style.display = 'block';
      if (rawPanel) {
        rawPanel.style.display = 'none';
        rawPanel.classList.remove('active');
      }
    }
  },

  async analyzeRawText() {
    const textarea = document.getElementById('raw-email-input');
    if (!textarea) return;
    const text = textarea.value.trim();
    if (!text) {
      this.showToast('Por favor pegue el contenido o cabeceras del correo.', 'error');
      return;
    }

    this.showLoading(true);
    this.showToast('Analizando texto plano del correo...', 'info');

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filename: 'correo_texto_plano.eml',
          rawText: text
        })
      });

      const result = await response.json();
      if (result.success) {
        this.renderAnalysis(result.data);
        this.showToast('¡Análisis de texto plano completado!', 'success');
        this.loadHistory();
      } else {
        this.showToast(`Error al procesar: ${result.error}`, 'error');
      }
    } catch (err) {
      this.showToast(`Error de análisis: ${err.message}`, 'error');
    } finally {
      this.showLoading(false);
    }
  },

  async pasteFromClipboard() {
    const textarea = document.getElementById('raw-email-input');
    if (!textarea) return;
    try {
      if (navigator.clipboard && navigator.clipboard.readText) {
        const text = await navigator.clipboard.readText();
        if (text) {
          textarea.value = text;
          this.showToast('Texto pegado desde el portapapeles.', 'success');
        } else {
          this.showToast('El portapapeles está vacío.', 'error');
        }
      } else {
        textarea.focus();
        this.showToast('Use Ctrl+V para pegar en el cuadro de texto.', 'info');
      }
    } catch (err) {
      textarea.focus();
      this.showToast('Permiso de portapapeles no disponible. Use Ctrl+V.', 'info');
    }
  },

  clearRawText() {
    const textarea = document.getElementById('raw-email-input');
    if (textarea) {
      textarea.value = '';
      this.showToast('Cuadro de texto limpiado.', 'info');
    }
  },

  exportAnalysisHtml() {
    if (!this.currentAnalysis) {
      this.showToast('No hay ningún análisis activo para exportar.', 'error');
      return;
    }
    const htmlReport = Components.generateHtmlReport(this.currentAnalysis);
    const blob = new Blob([htmlReport], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const cleanFn = (this.currentAnalysis.filename || 'correo').replace(/[^a-zA-Z0-9_-]/g, '_');
    a.download = `Informe_Forense_ForensicBuzMail_${cleanFn}_${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
    this.showToast('¡Informe HTML generado y descargado con éxito!', 'success');
  },

  exportAnalysisJson() {
    if (!this.currentAnalysis) return;
    const jsonStr = JSON.stringify(this.currentAnalysis, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forense_${this.currentAnalysis.filename}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    this.showToast('Informe JSON exportado.', 'success');
  },

  showToast(msg, type = 'info') {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = msg;
    toast.className = 'show';
    if (type === 'error') toast.style.borderColor = '#ef4444';
    else if (type === 'success') toast.style.borderColor = '#10b981';
    else toast.style.borderColor = 'var(--border-color)';

    setTimeout(() => {
      toast.className = '';
    }, 3500);
  },

  showLoading(isLoading) {
    const loader = document.getElementById('global-loader');
    if (loader) loader.style.display = isLoading ? 'flex' : 'none';
  },

  async geolocateIp(ip) {
    if (!ip || ip === 'No detectada' || ip === 'Desconocido' || ip === 'N/A') {
      this.showToast('Dirección IP no válida para geolocalización.', 'error');
      return;
    }

    const modal = document.getElementById('geo-modal');
    const titleEl = document.getElementById('modal-ip-title');
    const bodyEl = document.getElementById('modal-geo-body');

    if (titleEl) titleEl.textContent = `IP: ${ip}`;
    if (bodyEl) {
      bodyEl.innerHTML = `
        <div style="text-align: center; padding: 2.5rem 1rem; color: var(--text-secondary);">
          <div style="font-size: 2.2rem; margin-bottom: 0.75rem;">🌐</div>
          <div style="font-weight: 600; color: #fff; margin-bottom: 0.35rem;">Consultando Localización de ${Components.escapeHtml(ip)}...</div>
          <p style="font-size: 0.82rem; color: var(--text-muted);">Consultando registros RIR, ASN y geolocalización...</p>
        </div>
      `;
    }
    if (modal) modal.style.display = 'flex';

    try {
      const response = await fetch(`/api/geolocate?ip=${encodeURIComponent(ip)}`);
      const result = await response.json();
      if (result.success && result.data) {
        if (bodyEl) bodyEl.innerHTML = Components.renderGeoModalContent(result.data);
      } else {
        if (bodyEl) bodyEl.innerHTML = `<div style="color: #ef4444; padding: 2rem; text-align: center;">Error al obtener datos: ${Components.escapeHtml(result.error || 'Desconocido')}</div>`;
      }
    } catch (err) {
      if (bodyEl) bodyEl.innerHTML = `<div style="color: #ef4444; padding: 2rem; text-align: center;">Fallo de conexión: ${Components.escapeHtml(err.message)}</div>`;
    }
  },

  closeGeoModal() {
    const modal = document.getElementById('geo-modal');
    if (modal) modal.style.display = 'none';
  },

  async lookupSidebarIp() {
    const input = document.getElementById('quick-ip-input');
    if (!input) return;
    const ip = input.value.trim();
    if (!ip) {
      this.showToast('Por favor ingrese una dirección IP.', 'info');
      return;
    }
    this.geolocateIp(ip);
  },

  arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }
};

window.addEventListener('DOMContentLoaded', () => App.init());

