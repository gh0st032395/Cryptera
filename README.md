# Cryptera

**Cryptera** è un'applicazione desktop per la cifratura locale di file e cartelle,
costruita su un core crittografico in Rust e un'interfaccia grafica Tauri + Web.

> Nessun cloud. Nessun servizio esterno. I dati rimangono esclusivamente sul dispositivo.

---

## Indice

1. [Caratteristiche](#caratteristiche)
2. [Stack tecnologico](#stack-tecnologico)
3. [Requisiti](#requisiti)
4. [Build e avvio](#build-e-avvio)
5. [Utilizzo](#utilizzo)
6. [Profili di sicurezza e integrità](#profili-di-sicurezza-e-integrità)
7. [Formato dei file `.ecf`](#formato-dei-file-ecf)
8. [Struttura del progetto](#struttura-del-progetto)
9. [Versionamento](#versionamento)
10. [Sicurezza](#sicurezza)
11. [Licenza](#licenza)

---

## Caratteristiche

| Funzionalità | Dettagli |
|---|---|
| **Cifratura** | File singoli e cartelle intere (archivio TAR automatico) |
| **Algoritmo** | AES-256-GCM — cifratura autenticata AEAD |
| **KDF** | Argon2id — resistente ad attacchi GPU e side-channel |
| **FEC** | Reed-Solomon su GF(256) — recupero da corruzione fisica |
| **Compressione** | Pre-cifratura: zlib / LZMA2; archivi: gzip / bzip2 / xz |
| **Verifica integrità** | Senza decifrare l'output — solo lettura e autenticazione GCM |
| **Batch Decrypt** | Decifratura multipla con unica password e stato per-file |
| **Audit Log** | Log JSONL persistente di tutte le operazioni (locale) |
| **Storico** | Ring-buffer in memoria degli ultimi 100 eventi (volatile) |
| **Tema** | Dark / Light / System — persisto in `localStorage` |
| **System Tray** | Chiusura → hide to tray; ripristino con doppio click o menu |
| **Internazionalizzazione** | Italiano e Inglese, selezionabili a runtime |
| **Drag & Drop** | File e cartelle trascinabili direttamente nei pannelli |

---

## Stack tecnologico

```
┌──────────────────────────────────────────────────────────┐
│   Frontend  (ui/)                                        │
│   HTML + CSS (custom properties) + ES Modules (no build) │
│   i18n bilingue EN/IT · Tema dark/light/system           │
├──────────────────────────────────────────────────────────┤
│   Bridge  (Tauri v2 IPC)                                 │
│   Tauri commands · Events (progress/status) · Dialog API │
├──────────────────────────────────────────────────────────┤
│   Backend  (src-tauri/)                                  │
│   Rust 2021 · tauri v2.5 · secrecy · serde_json         │
│   Tray icon · Audit JSONL · ControlFlags (cancel/pause)  │
├──────────────────────────────────────────────────────────┤
│   Crypto Core  (src/ — crypto_core_rs)                   │
│   AES-256-GCM · Argon2id · Reed-Solomon · Header v4      │
└──────────────────────────────────────────────────────────┘
```

---

## Requisiti

| Componente | Versione minima |
|---|---|
| Rust toolchain | 1.77+ (edition 2021) |
| Tauri CLI | 2.x (`cargo install tauri-cli`) |
| Node.js | Non richiesto — frontend è HTML/JS puro, nessun bundler |
| Sistema operativo | Windows 10+, macOS 12+, Linux (GTK 3) |

> Su Linux, assicurarsi di avere installato i pacchetti di sistema per Tauri/WebKit:
> `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`

---

## Build e avvio

### Sviluppo (hot-reload)

```bash
# dalla root del repository
cargo tauri dev
```

### Build di produzione

```bash
cargo tauri build
# gli installer si trovano in: src-tauri/target/release/bundle/
```

### Solo il core crittografico (test)

```bash
cargo test                        # test core
cargo test --manifest-path src-tauri/Cargo.toml  # test Tauri backend
```

### Verifica versioni

```bash
# controlla che VERSION, Cargo.toml, src-tauri/Cargo.toml e tauri.conf.json siano allineate
pwsh ./scripts/check-version.ps1
```

---

## Utilizzo

### Cifratura

1. Selezionare la modalità **File** o **Cartella** nel tab *Encrypt*.
2. Scegliere sorgente, destinazione, password e profili.
3. Click **Start Encryption**.

Il file di output ha estensione `.ecf`. Il file originale non viene rimosso.

### Decifratura

1. Selezionare il file `.ecf` nel tab *Decrypt*.
2. Inserire la password (e il keyfile, se usato in fase di cifratura).
3. Scegliere la cartella di destinazione.
4. Click **Start Decryption**.

I metadati (tipo, dimensioni, profilo FEC) vengono mostrati automaticamente al
caricamento del file.

### Verifica integrità

Il tab *Verify* autentica l'header e tutti gli shard GCM senza scrivere output.
Mostra:
- ✓/✗ stato integrità
- Configurazione k/r Reed-Solomon
- Overhead FEC percentuale
- Dimensione del plaintext

### Batch Decrypt

Nel tab *Batch*:
1. Aggiungere uno o più file `.ecf` (o trascinarli).
2. Inserire la password comune.
3. Click **Start Batch Decrypt**.

Ogni file viene elaborato in sequenza; lo stato (OK / ERR) è visibile per-file
in tempo reale.

### Audit Log

Il tab *Audit* mostra il log JSONL persistente.
Percorso predefinito:
- **Windows**: `%APPDATA%\Cryptera\logs\audit.jsonl`
- **Linux / macOS**: `~/.local/share/cryptera/logs/audit.jsonl`

Ogni voce contiene: timestamp UTC, operazione, file, dimensione, durata, stato.

### System Tray

Cliccando **×** la finestra si nasconde nel system tray.
Doppio click sull'icona tray (o menu contestuale → *Open Cryptera*) ripristina la
finestra. Per chiudere definitivamente: menu tray → **Quit**.

---

## Profili di sicurezza e integrità

### Profili Argon2id (KDF)

| Profilo | Iterazioni | Memoria | Parallelismo | Uso consigliato |
|---|---|---|---|---|
| **Standard** | 3 | 64 MB | 2 | Uso quotidiano (default) |
| **Strong** | 6 | 256 MB | 4 | File sensibili |
| **Paranoid** | 10 | 512 MB | 8 | Massima protezione, più lento |

### Profili Reed-Solomon (FEC)

| Profilo | Dati (k) | Parità (r) | Overhead | Recuperabile fino a |
|---|---|---|---|---|
| **Low** | 28 | 4 | ~14% | 12% corruzione |
| **Medium** | 24 | 8 | ~33% | 25% corruzione (default) |
| **High** | 12 | 12 | ~100% | 50% corruzione |
| **Max** | 8 | 24 | ~300% | 75% corruzione |

---

## Formato dei file `.ecf`

I file cifrati usano il formato header v4 (proprietario):

```
┌─────────────────────────────────────────────────────┐
│  Magic + Version (4 bytes)                          │
│  Salt Argon2id (16 bytes)                           │
│  Argon2 params (t, m, p)                            │
│  Flags (compressione, container, hide-filename, ...) │
│  Filename originale (opzionale, in chiaro,          │
│    autenticato — NON cifrato)                       │
│  Password check record (opzionale, HMAC del salt)   │
│  N shard cifrati (AES-256-GCM)                      │
│    → ognuno con nonce 12b + tag 16b + CRC32         │
│  R shard di parità Reed-Solomon                     │
└─────────────────────────────────────────────────────┘
```

L'header è incluso come **AAD** in ogni operazione GCM: qualsiasi modifica
all'header invalida l'autenticazione. Non esiste modalità "solo cifratura senza
autenticazione".

> **Nota privacy**: il nome file originale, se memorizzato, è leggibile da
> chiunque apra il file `.ecf` (è autenticato ma non cifrato). Per non esporre
> il nome, abilitare l'opzione **Hide original filename** in fase di cifratura.

---

## Struttura del progetto

```
cryptov2/
├── src/                    # Crypto core (lib crate: crypto_core_rs)
│   └── lib.rs              # AES-GCM, Argon2id, Reed-Solomon, header v4
├── src-tauri/              # Tauri backend (bin crate: crypto_tauri)
│   ├── src/
│   │   ├── main.rs         # Tauri commands, AppState, AuditState, system tray
│   │   └── audit.rs        # JSONL audit logger
│   ├── capabilities/
│   │   └── default.json    # Tauri permission capabilities
│   └── tauri.conf.json     # App config (nome, finestra, bundle)
├── ui/                     # Frontend (HTML + CSS + ES Modules, nessun build step)
│   ├── index.html          # Layout principale, tutti i pannelli
│   ├── styles.css          # Design system con CSS variables dark/light
│   ├── app.js              # Logica UI, handlers, theme, history, batch, audit
│   ├── loader.js           # Entry point (import dinamico di app.js)
│   └── modules/
│       ├── i18n.js         # Traduzioni EN / IT
│       ├── tauri-bridge.js # Wrapper invoke/event/dialog/window
│       └── ui-state.js     # Stato condiviso (busy, progress, meta render)
├── fuzz/                   # Fuzzing harness (cargo-fuzz)
├── tests/                  # Test di regressione crittografica
├── scripts/
│   └── check-version.ps1   # Verifica allineamento versioni
├── VERSION                 # Fonte ufficiale della versione
├── CHANGELOG.md
├── SECURITY.md             # Threat model, primitive crittografiche
└── RELEASE.md              # Procedura di rilascio
```

---

## Versionamento

Il progetto usa **Semantic Versioning** (`MAJOR.MINOR.PATCH`):

| Tipo di cambiamento | Bump |
|---|---|
| Breaking change al formato `.ecf` o alle API | MAJOR |
| Nuova funzionalità retrocompatibile | MINOR |
| Bug fix, refactoring, aggiornamenti dipendenze | PATCH |

La versione corrente è definita in `VERSION` e **deve essere identica** in:
- `VERSION`
- `Cargo.toml` (crypto_core_rs)
- `src-tauri/Cargo.toml`
- `src-tauri/tauri.conf.json`

Per verificare l'allineamento:

```powershell
pwsh ./scripts/check-version.ps1
```

Per rilasciare una nuova versione, seguire la procedura in [`RELEASE.md`](RELEASE.md).

---

## Sicurezza

Per il dettaglio delle primitive crittografiche, garanzie di sicurezza, threat
model e vulnerabilità note, consultare [`SECURITY.md`](SECURITY.md).

**Segnalazione vulnerabilità**: aprire una issue privata o contattare il
maintainer direttamente. Non pubblicare vulnerabilità come issue pubbliche.

---

## Licenza

Dual license **MIT OR Apache-2.0** — vedere i file `LICENSE-MIT` e
`LICENSE-APACHE` (o `license = "MIT OR Apache-2.0"` nei file `Cargo.toml`).
