# ForensicBuzMail ⚡
### Analizador Forense de Protocolos y Correos Electrónicos (.eml, .msg y Texto Plano)
**Modo SaaS Dark Mode // 100% Entorno Local y Privado**

---

## 🛡️ Descripción General
**ForensicBuzMail** es una plataforma de análisis e investigación forense de correos electrónicos diseñada para analistas de ciberseguridad, peritos judiciales informáticos, equipos SOC e investigadores de amenazas (DFIR).

La aplicación permite:
1. **Arrastrar y soltar** archivos de correo estándar **`.eml`** (RFC 5322) y archivos de Microsoft Outlook **`.msg`** (Compound File Binary Format / OLE2).
2. **Pegar texto plano o cabeceras raw** directamente desde el portapapeles (compatible con **Gmail "Mostrar original"**, resúmenes y copias web en español).
3. Auditar exhaustivamente los protocolos de autenticación (**SPF**, **DKIM**, **DMARC**) y comprobar la alineación estricta/relajada con el remitente visible.
4. Reconstruir la ruta de saltos de red SMTP (**SMTP Relays**) con latencias intermedias e identificación de la **IP pública real de origen**.
5. **Clasificación y geolocalización de IPs**: método **100% offline** (asignaciones IANA por octeto, RIRs RIPE/ARIN/APNIC/LACNIC/AFRINIC, redes corporativas) con opción de **consulta online enriquecida** (coordenadas, Google Maps, VirusTotal, AbuseIPDB).
6. Calcular un índice cuantitativo de riesgo (**0-100**) contra ataques de Phishing, Spoofing de marcas, inconsistencias de Return-Path/Reply-To y malware adjunto.
7. **Exportar informes periciales completos en formato HTML** interactivo e imprimible (con el emblema oficial incrustado en base64) o formato JSON estructurado.

---

## 🔒 100% Local, Seguro y Privado
- **Cero Llamadas Externas Obligatorias**: Todo el análisis de correos, cabeceras, adjuntos, protocolos y clasificación de IPs se ejecuta estrictamente en la máquina local. La geolocalización online es puramente optativa a petición del usuario.
- **Persistencia en SQLite Local**: Utiliza almacenamiento local en `data/forensics.sqlite` con historial de análisis, búsqueda instantánea y estadísticas.
- **Aislamiento Seguro contra Inyecciones (XSS)**: Las vistas previas de contenido HTML se ejecutan dentro de un contenedor `<iframe>` aislado (`sandbox="allow-same-origin"`) sin permisos de ejecución de scripts, bloqueando rastreadores web (web beacons) y cargas dinámicas.

---

## 🚀 Requisitos y Puesta en Marcha

### Requisitos:
- **Node.js**: Versión 18+ (Node.js 22 recomendada, instalada en el sistema).
- **Cero dependencias npm externas**: El proyecto ha sido programado de forma pura y autosuficiente utilizando módulos nativos y estándares de red.
- **Python 3** (disponible mediante el comando oficial `py` o `python`) **O** **Node.js** (versión 18+).
- **Cero dependencias externas**: Implementado con módulos nativos y estándares de red.

### Inicio Rápido (1 Clic en Windows):
Simplemente haga doble clic en el archivo:
```bat
iniciar.bat
```
*(O ejecute `.\iniciar.ps1` en PowerShell)*.

El script detectará automáticamente Node.js, iniciará el servidor HTTP local y abrirá su navegador en:
El script detectará automáticamente el motor disponible, iniciará el servidor local en el puerto `8080` (con resolución automática de conflictos) y abrirá su navegador en:
```
http://127.0.0.1:3000
http://127.0.0.1:8080
```

### Ejecución Manual vía Terminal:
```bash
# Con Python (recomendado):
py server.py

# O con Node.js:
node server.js
```

### Ejecución de Pruebas Automatizadas:
```bash
node tests/test_suite.js
```

---

## 🧩 Funcionalidades y Protocolos Analizados
## 🧩 Nuevas Funcionalidades en ForensicBuzMail v1.1.0

### 1. Sender Policy Framework (SPF - RFC 7208)
- Extracción y decodificación de `Received-SPF` y veredictos en `Authentication-Results`.
- Detección de estados: `pass`, `fail` (-all), `softfail` (~all), `neutral` (?all), `none`, `permerror`, `temperror`.
- Identificación de la IP cliente de envío y del envelope sender (`smtp.mailfrom` / `Return-Path`).
- **Verificación de Alineación**: Compara el dominio del remitente visible (`From:`) con el dominio autenticado por SPF.
### 1. Entrada y Análisis de Texto Plano / Cabeceras Raw
- Nuevo selector de modo en la interfaz: **📂 Subir Archivo** o **📝 Pegar Texto Plano / Cabeceras**.
- Permite pegar fragmentos de cabeceras (`Received:`, `Authentication-Results:`, `From:`, etc.) o el correo completo.
- Botón **"📋 Pegar Portapapeles"** y **"🚀 Analizar Texto Forense"** para agilizar investigaciones urgentes sin generar archivos temporales en disco.

### 2. DomainKeys Identified Mail (DKIM - RFC 6376)
- Inspección de todas las firmas digitales presentes (`DKIM-Signature`).
- Extracción de etiquetas: `v` (versión), `a` (algoritmo, ej. `rsa-sha256`), `d` (dominio firmante), `s` (selector), `h` (cabeceras firmadas), `bh` (hash del cuerpo), `b` (firma).
- Detección de algoritmos débiles u obsoletos (ej. firmas SHA-1 vulnerables a colisiones).
- **Alineación DKIM**: Comprueba si el dominio firmante `d=` coincide con el dominio del remitente visible.
### 2. Exportación de Informe Forense en HTML
- Botón **"📄 Exportar Informe HTML"** en la barra lateral del veredicto.
- Genera un archivo HTML autosuficiente, sin dependencias externas, con diseño ejecutivo oscuro y optimizado para impresión:
  - Resumen ejecutivo con medidor de riesgo.
  - Tabla de metadatos e identificación del mensaje.
  - Matriz de protocolos de autenticación (SPF, DKIM, DMARC) con explicaciones técnicas.
  - Trazabilidad completa de saltos de red SMTP.
  - Detalle de vectores de amenaza y deducciones de puntuación.
  - Listado de adjuntos con sumas criptográficas SHA-256 y MD5.
  - Cabeceras originales íntegras.
  - Botón directo de **"🖨️ Imprimir / Guardar en PDF"**.

### 3. DMARC (RFC 7489)
- Comprobación de alineación dual de identificadores (SPF Alignment + DKIM Alignment) en modo estricto o relajado.
- Extracción de la política del dominio receptor y declarado (`p=reject`, `p=quarantine`, `p=none`).
- Análisis de la acción recomendada por el dominio emisor para proteger su marca.

### 4. Trazabilidad de Red (SMTP Hops) e IP de Origen
- Reconstrucción cronológica inversa de la cadena de servidores MTA a partir de las cabeceras `Received:`.
- Para cada salto: MTA emisor (`from`), MTA receptor (`by`), protocolo/cifrado (`ESMTPS`, `TLS`), timestamp y cálculo de latencia entre saltos sucesivos.
- **Identificación de la IP de Origen**: Localiza el primer salto que conecta el cliente a una IP pública de Internet, distinguiendo IPs privadas o de loopback (RFC 1918).

### 5. Motor de Puntuación de Riesgo Forense (Score 0 - 100)
- **Nivel Bajo (0 - 20)**: Correo auténtico que supera las validaciones criptográficas sin discrepancias.
- **Nivel Moderado (21 - 50)**: Falta de firmas DKIM o políticas SPF permisivas.
- **Nivel Alto (51 - 79)**: Discrepancias graves entre `From`, `Return-Path` o `Reply-To`.
- **Nivel Crítico (80 - 100)**: Fallo directo en SPF/DMARC con suplantación de identidad (Spoofing) o presencia de archivos ejecutables maliciosos adjuntos (.exe, .vbs, .scr, .iso, etc.).

### 6. Análisis de Adjuntos y Hashes Criptográficos
- Extracción de archivos adjuntos tanto en `.eml` como en `.msg`.
- Cálculo instantáneo de sumas de verificación **SHA-256** y **MD5** para correlación con bases de datos de Inteligencia de Amenazas (VirusTotal, AlienVault OTX, etc.).
- Alerta visual inmediata en caso de extensiones peligrosas para la máquina del usuario.

### 7. Historial y Auditoría en Base de Datos
- Tabla interactiva con búsqueda por asunto, remitente o IP.
- Opción de recargar cualquier análisis previo con un solo clic.
- Exportación del informe forense completo en formato JSON estructurado.

---

## 📂 Estructura del Proyecto
## 📂 Estructura del Proyecto en `E:\App\parseador`
```
E:\App\parseador/
├── server.js               # Servidor HTTP local y API REST
├── database.js             # Persistencia local con SQLite y fallback JSON
├── server.py               # Servidor forense en Python 3 puro (HTTP + REST API)
├── server.js               # Servidor forense en Node.js
├── database.js             # Capa de base de datos SQLite para Node
├── package.json            # Metadatos del proyecto
├── iniciar.bat             # Lanzador rápido de un clic para Windows
├── iniciar.ps1             # Lanzador para PowerShell
├── README.md               # Documentación técnica completa
├── parsers/
│   ├── mime_parser.js      # Parser RFC 5322 (.eml)
│   ├── msg_parser.js       # Parser OLE2 CFBF (.msg)
│   └── header_analyzer.js  # Reconstructor de saltos Received e IP de origen
├── security/
│   ├── spf_analyzer.js     # Analizador de SPF y alineación
│   ├── dkim_analyzer.js    # Analizador de firmas DKIM
│   ├── dmarc_analyzer.js   # Analizador de políticas DMARC
│   └── risk_engine.js      # Motor cuantitativo de riesgo
├── public/                 # Interfaz de Usuario SaaS Dark Mode
│   ├── index.html          # Interfaz web con pestañas y Drag & Drop
│   ├── css/style.css       # Estilos Dark Mode personalizados
│   ├── index.html          # UI con Drag & Drop, entrada de texto y reportes
│   ├── css/style.css       # Estilos Dark Mode y vista de impresión
│   └── js/
│       ├── app.js          # Lógica reactiva de cliente
│       └── components.js   # Componentes visuales y sanitizador
├── samples/                # Muestras de correos listas para pruebas
│       ├── app.js          # Lógica reactiva, entrada de texto y exportaciones
│       └── components.js   # Renderizadores y generador del informe HTML
├── samples/                # Muestras forenses listas para pruebas
│   ├── legitimate_email.eml# Muestra legítima autenticada
│   ├── phishing_spoof.eml  # Muestra de phishing con suplantación y malware
│   └── invoice_sample.msg  # Muestra nativa en formato Outlook .msg
├── tests/
│   ├── test_suite.js       # Suite de pruebas automatizadas
│   └── create_sample_msg.js# Generador de estructura binaria .msg
│   ├── test_suite.js       # Suite de pruebas Node.js (10/10 PASS)
│   └── test_python_engine.py # Suite de pruebas Python (3/3 PASS)
└── data/
    └── forensics.sqlite    # Base de datos SQLite local (creada en la 1ª ejecución)
    └── forensics.sqlite    # Base de datos SQLite local
```
