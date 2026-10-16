/**
 * Local Forensic Database Persistence Module
 * Uses native Node.js 22 SQLite (node:sqlite) with automatic local JSON fallback.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

class ForensicDatabase {
  constructor(dataDir) {
    this.dataDir = dataDir || path.join(__dirname, 'data');
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }

    this.dbPath = path.join(this.dataDir, 'forensics.sqlite');
    this.jsonFallbackPath = path.join(this.dataDir, 'history.json');
    this.sqliteDb = null;
    this.useFallback = false;

    this.init();
  }

  init() {
    try {
      const { DatabaseSync } = require('node:sqlite');
      this.sqliteDb = new DatabaseSync(this.dbPath);
      
      // Initialize schema
      this.sqliteDb.exec(`
        CREATE TABLE IF NOT EXISTS analyses (
          id TEXT PRIMARY KEY,
          created_at TEXT NOT NULL,
          filename TEXT NOT NULL,
          file_type TEXT NOT NULL,
          file_size INTEGER NOT NULL,
          subject TEXT,
          sender TEXT,
          recipient TEXT,
          origin_ip TEXT,
          spf_status TEXT,
          dkim_status TEXT,
          dmarc_status TEXT,
          risk_score INTEGER NOT NULL,
          risk_level TEXT NOT NULL,
          attachments_count INTEGER DEFAULT 0,
          analysis_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_analyses_risk ON analyses(risk_level);
      `);
      console.log('[DB] SQLite nativo inicializado en:', this.dbPath);
    } catch (err) {
      console.warn('[DB] No se pudo inicializar node:sqlite, usando persistencia JSON local:', err.message);
      this.useFallback = true;
      if (!fs.existsSync(this.jsonFallbackPath)) {
        fs.writeFileSync(this.jsonFallbackPath, JSON.stringify([], null, 2), 'utf-8');
      }
    }
  }

  saveAnalysis(analysis) {
    const id = analysis.id || crypto.randomUUID();
    analysis.id = id;
    const createdAt = new Date().toISOString();

    const record = {
      id,
      created_at: createdAt,
      filename: analysis.filename || 'correo_desconocido',
      file_type: analysis.fileType || 'eml',
      file_size: analysis.fileSize || 0,
      subject: analysis.email?.subject || '(Sin asunto)',
      sender: analysis.email?.from?.address || 'Desconocido',
      recipient: (analysis.email?.to || []).map(t => t.address).join(', ') || 'Desconocido',
      origin_ip: analysis.network?.originIp || 'No detectada',
      spf_status: analysis.spf?.status || 'none',
      dkim_status: analysis.dkim?.status || 'none',
      dmarc_status: analysis.dmarc?.status || 'none',
      risk_score: analysis.risk?.score || 0,
      risk_level: analysis.risk?.level || 'low',
      attachments_count: analysis.email?.attachments?.length || 0,
      analysis_json: JSON.stringify(analysis)
    };

    if (!this.useFallback && this.sqliteDb) {
      try {
        const stmt = this.sqliteDb.prepare(`
          INSERT INTO analyses (
            id, created_at, filename, file_type, file_size, subject,
            sender, recipient, origin_ip, spf_status, dkim_status,
            dmarc_status, risk_score, risk_level, attachments_count, analysis_json
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(
          record.id, record.created_at, record.filename, record.file_type,
          record.file_size, record.subject, record.sender, record.recipient,
          record.origin_ip, record.spf_status, record.dkim_status,
          record.dmarc_status, record.risk_score, record.risk_level,
          record.attachments_count, record.analysis_json
        );
        return id;
      } catch (e) {
        console.error('[DB] Error guardando en SQLite, guardando en fallback:', e.message);
      }
    }

    // JSON Fallback
    try {
      const list = this._readJsonFallback();
      list.unshift(record);
      if (list.length > 500) list.pop(); // Keep last 500 records
      fs.writeFileSync(this.jsonFallbackPath, JSON.stringify(list, null, 2), 'utf-8');
      return id;
    } catch (e) {
      console.error('[DB] Error en persistencia JSON:', e.message);
      return id;
    }
  }

  getHistory(limit = 50, offset = 0, query = '') {
    if (!this.useFallback && this.sqliteDb) {
      try {
        let sql = `
          SELECT id, created_at, filename, file_type, file_size, subject,
                 sender, recipient, origin_ip, spf_status, dkim_status,
                 dmarc_status, risk_score, risk_level, attachments_count
          FROM analyses
        `;
        const params = [];
        if (query && query.trim().length > 0) {
          sql += ` WHERE subject LIKE ? OR sender LIKE ? OR origin_ip LIKE ? OR filename LIKE ? `;
          const q = `%${query.trim()}%`;
          params.push(q, q, q, q);
        }
        sql += ` ORDER BY created_at DESC LIMIT ? OFFSET ? `;
        params.push(limit, offset);

        const stmt = this.sqliteDb.prepare(sql);
        return stmt.all(...params);
      } catch (e) {
        console.error('[DB] Error al consultar SQLite:', e.message);
      }
    }

    // JSON Fallback
    const list = this._readJsonFallback();
    let filtered = list;
    if (query && query.trim().length > 0) {
      const q = query.trim().toLowerCase();
      filtered = list.filter(r => 
        (r.subject || '').toLowerCase().includes(q) ||
        (r.sender || '').toLowerCase().includes(q) ||
        (r.origin_ip || '').toLowerCase().includes(q) ||
        (r.filename || '').toLowerCase().includes(q)
      );
    }
    return filtered.slice(offset, offset + limit).map(r => ({
      id: r.id,
      created_at: r.created_at,
      filename: r.filename,
      file_type: r.file_type,
      file_size: r.file_size,
      subject: r.subject,
      sender: r.sender,
      recipient: r.recipient,
      origin_ip: r.origin_ip,
      spf_status: r.spf_status,
      dkim_status: r.dkim_status,
      dmarc_status: r.dmarc_status,
      risk_score: r.risk_score,
      risk_level: r.risk_level,
      attachments_count: r.attachments_count
    }));
  }

  getAnalysisById(id) {
    if (!this.useFallback && this.sqliteDb) {
      try {
        const stmt = this.sqliteDb.prepare(`SELECT analysis_json FROM analyses WHERE id = ?`);
        const row = stmt.get(id);
        if (row && row.analysis_json) {
          return JSON.parse(row.analysis_json);
        }
      } catch (e) {
        console.error('[DB] Error leyendo análisis en SQLite:', e.message);
      }
    }

    const list = this._readJsonFallback();
    const found = list.find(r => r.id === id);
    if (found && found.analysis_json) {
      return JSON.parse(found.analysis_json);
    }
    return null;
  }

  deleteAnalysis(id) {
    if (!this.useFallback && this.sqliteDb) {
      try {
        const stmt = this.sqliteDb.prepare(`DELETE FROM analyses WHERE id = ?`);
        stmt.run(id);
      } catch (e) {
        console.error('[DB] Error borrando en SQLite:', e.message);
      }
    }

    const list = this._readJsonFallback();
    const updated = list.filter(r => r.id !== id);
    fs.writeFileSync(this.jsonFallbackPath, JSON.stringify(updated, null, 2), 'utf-8');
    return true;
  }

  getStats() {
    let history = this.getHistory(1000, 0, '');
    const total = history.length;
    let critical = 0, high = 0, medium = 0, low = 0;
    let scoreSum = 0;

    for (const h of history) {
      scoreSum += h.risk_score || 0;
      if (h.risk_level === 'critical') critical++;
      else if (h.risk_level === 'high') high++;
      else if (h.risk_level === 'medium') medium++;
      else low++;
    }

    return {
      total,
      critical,
      high,
      medium,
      low,
      averageScore: total > 0 ? Math.round(scoreSum / total) : 0
    };
  }

  _readJsonFallback() {
    try {
      if (!fs.existsSync(this.jsonFallbackPath)) return [];
      const content = fs.readFileSync(this.jsonFallbackPath, 'utf-8');
      return JSON.parse(content || '[]');
    } catch {
      return [];
    }
  }
}

module.exports = ForensicDatabase;

