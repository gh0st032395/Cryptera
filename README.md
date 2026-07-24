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
6. [CLI: uso da script](#cli-uso-da-script)
7. [Profili di sicurezza e integrità](#profili-di-sicurezza-e-integrità)
8. [Formato dei file `.ecf`](#formato-dei-file-ecf)
9. [Struttura del progetto](#struttura-del-progetto)
10. [Versionamento](#versionamento)
11. [Sicurezza](#sicurezza)
12. [Licenza](#licenza)

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
| **Associazione file** | I file `.ecf` si aprono con doppio click sul pannello Decrypt |
| **CLI** | Eseguibile `cryptera` per script su Windows/macOS/Linux, output JSON |
| **Telemetria** | **Nessuna** — nessun tracciamento, nessuna analitica |
| **Aggiornamenti** | In-app, firmati e verificati; controllo **manuale** dal pannello About |

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
├────────────────────────────┬─────────────────────────────┤
│   Shared ops (ops/)        │   CLI  (cli/ — `cryptera`)   │
│   TAR · estrazione sicura  │   script-friendly · JSON     │
│   profili sec/int          │   exit code stabili          │
├────────────────────────────┴─────────────────────────────┤
│   Crypto Core  (src/ — crypto_core_rs)                   │
│   AES-256-GCM · Argon2id · Reed-Solomon · Header v5      │
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

## Installazione (utenti)

Gli installer per Windows (`.msi` / NSIS), macOS (`.dmg` universale) e Linux
(`.deb` / `.rpm` / AppImage) sono pubblicati nelle
[GitHub Releases](https://github.com/gh0st032395/Cryptera/releases).
Verificare l'integrità dei download con il file `SHA256SUMS.txt` allegato a
ogni release:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

> Nota: i binari non sono ancora firmati (Authenticode / notarizzazione Apple):
> Windows SmartScreen e macOS Gatekeeper mostreranno un avviso al primo avvio.

### Aggiornamenti

Cryptera include un updater integrato: dal pannello *About*, premendo
**"Controlla aggiornamenti"**, verifica la presenza di una nuova versione e,
su conferma, la scarica, **ne verifica la firma crittografica** e la installa.
L'updater è **l'unico** componente che accede alla rete (lato Rust, verso
GitHub Releases); le operazioni di cifratura restano completamente offline e la
webview mantiene `connect-src 'none'`. Non viene effettuato alcun controllo
automatico all'avvio: l'app non esegue alcuna chiamata di rete finché non è
l'utente a richiederlo esplicitamente.

> ⚠️ **Non esiste recupero password**: senza password (e keyfile, se usato)
> i dati cifrati sono irrecuperabili. Conservala in un password manager.

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
cargo test                                       # test core
cargo test --manifest-path ops/Cargo.toml        # test livello condiviso (TAR/estrazione)
cargo test --manifest-path cli/Cargo.toml        # test CLI (unit + roundtrip end-to-end)
cargo test --manifest-path src-tauri/Cargo.toml  # test Tauri backend
```

### CLI

```bash
cargo build --release --manifest-path cli/Cargo.toml
# binario: cli/target/release/cryptera
```

### Verifica versioni

```bash
# controlla che VERSION, Cargo.toml, ops/, cli/, src-tauri/ e tauri.conf.json siano allineate
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

## CLI: uso da script

Oltre alla GUI, il repository produce un eseguibile autonomo **`cryptera`**
(crate `cli/`) che usa lo stesso core e lo stesso formato `.ecf`. Non apre
finestre e non richiede webview: è il modo supportato per automatizzare Cryptera
su **Windows, macOS e Linux** (backup notturni, pipeline CI, hook di deploy).

I binari sono allegati a ogni release GitHub:

| Piattaforma | Asset |
|---|---|
| Windows x86_64 | `cryptera-cli-windows-x86_64.zip` |
| macOS (universal, Intel + Apple Silicon) | `cryptera-cli-macos-universal.tar.gz` |
| Linux x86_64 | `cryptera-cli-linux-x86_64.tar.gz` |

Build locale:

```bash
cargo build --release --manifest-path cli/Cargo.toml
# binario: cli/target/release/cryptera (cryptera.exe su Windows)
```

### Comandi

| Comando | Cosa fa |
|---|---|
| `cryptera encrypt <file\|cartella>` | Cifra in un container `.ecf` (le cartelle passano da un TAR) |
| `cryptera decrypt <file.ecf>` | Decifra; i container cartella vengono estratti automaticamente |
| `cryptera verify <file.ecf>` | Verifica password e integrità senza scrivere nulla |
| `cryptera meta <file.ecf>` | Stampa i metadati dell'header — **senza password** |

`cryptera <comando> --help` elenca tutte le opzioni. Le principali di `encrypt`:
`--sec-profile`, `--int-profile`, `--file-comp`, `--folder-comp`, `--keyfile`,
`--hide-filename`, `--no-pwchk`, `--keep-symlinks`, `--force`.

### Password: mai sulla riga di comando

`--password` **non esiste**, di proposito: gli argomenti sono leggibili da
qualsiasi utente della macchina (`ps`, `/proc`, WMI) e finiscono nella cronologia
della shell. Le sorgenti accettate, in ordine di precedenza:

| Sorgente | Uso |
|---|---|
| `--password-stdin` | prima riga di stdin (pipe da un secret manager) |
| `--password-file <PATH>` | prima riga del file |
| `--password-env <VAR>` | variabile d'ambiente indicata |
| `$CRYPTERA_PASSWORD` | usata se non si passa nessun flag |
| prompt interattivo | solo se stdin è un terminale (con conferma su `encrypt`) |

Viene letta solo la prima riga e si rimuove il solo terminatore: spazi iniziali
e finali fanno parte della password.

### Output e codici di uscita

Con `--json` viene stampato su **stdout** un singolo oggetto JSON; senza,
stdout contiene solo il percorso prodotto. Avanzamento e messaggi vanno sempre su
**stderr**, così `--json` resta parsabile anche durante un job lungo. `--quiet`
azzera stderr.

| Codice | Significato |
|---|---|
| 0 | ok |
| 1 | errore generico (I/O, password mancante, …) |
| 2 | uso errato degli argomenti |
| 3 | password (o keyfile) sbagliata |
| 4 | file corrotto, troncato o non `.ecf` |
| 5 | l'output esiste già (serve `--force`) |
| 6 | operazione annullata |

### Esempi

```bash
# backup di una cartella, password da un file di secret
cryptera encrypt ~/Documenti --folder-comp gz -o /backup/docs.ecf \
  --password-file /run/secrets/cryptera --sec-profile strong

# verifica notturna di tutti i container, esce al primo problema
for f in /backup/*.ecf; do
  cryptera verify "$f" --quiet --password-env BACKUP_PW || exit $?
done

# ripristino, con estrazione automatica del container cartella
cryptera decrypt /backup/docs.ecf -o ~/restore --password-env BACKUP_PW

# ispezione senza password (JSON per jq)
cryptera meta /backup/docs.ecf --json | jq '.meta.plain_size, .meta.container'
```

```powershell
# Windows / PowerShell: password da variabile d'ambiente, con controllo dell'esito
$env:CRYPTERA_PASSWORD = (Get-Secret Cryptera -AsPlainText)
.\cryptera.exe encrypt C:\Dati\report.pdf -o D:\backup\report.ecf --json --quiet
switch ($LASTEXITCODE) {
  0 { "ok" }
  3 { "password errata" }
  5 { "output già presente" }
  default { "errore $LASTEXITCODE" }
}
```

> Non esiste ancora un comando batch: per più file si itera nella shell, come
> negli esempi. Il container prodotto dalla CLI è identico a quello della GUI e
> viceversa.

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

I file cifrati usano il formato header v5 (proprietario):

```
┌─────────────────────────────────────────────────────┐
│  Magic + Version (4 bytes)                          │
│  Salt Argon2id (16 bytes)                           │
│  Argon2 params (t, m, p)                            │
│  Flags (compressione, container, enc-filename, ...) │
│  Filename originale (opzionale, CIFRATO AES-GCM     │
│    nell'header — v5; in chiaro nei file v2–v4)      │
│  Header auth tag (HMAC, lega header e chiave)       │
│  Password check record (opzionale, AES-GCM)         │
│  N shard cifrati (AES-256-GCM)                      │
│    → ognuno con CRC32×2 + tag 16b (nonce derivato)  │
│  R shard di parità Reed-Solomon                     │
└─────────────────────────────────────────────────────┘
```

L'header è incluso come **AAD** in ogni operazione GCM: qualsiasi modifica
all'header invalida l'autenticazione. Non esiste modalità "solo cifratura senza
autenticazione".

> **Nota privacy**: dal formato v5 il nome file originale, se memorizzato, è
> cifrato nell'header ed è leggibile solo con la password corretta (i metadati
> senza password mostrano un segnaposto). I file creati con versioni
> precedenti (v2–v4) conservano il nome in chiaro finché non vengono
> ri-cifrati. Per non memorizzare alcun nome, abilitare l'opzione
> **Hide original filename** in fase di cifratura.

---

## Struttura del progetto

```
Cryptera/
├── src/                    # Crypto core (lib crate: crypto_core_rs)
│   └── lib.rs              # AES-GCM, Argon2id, Reed-Solomon, header v5
├── ops/                    # Livello condiviso GUI+CLI (lib crate: cryptera_ops)
│   └── src/lib.rs          # TAR, estrazione sicura, profili sec/int
├── cli/                    # CLI autonoma (bin crate: cryptera_cli → `cryptera`)
│   ├── src/main.rs         # comandi, dispatch, default dei percorsi
│   ├── src/password.rs     # sorgenti password (mai da argv)
│   ├── src/paths.rs        # output di default, sanitizzazione nomi da header
│   ├── src/report.rs       # output testuale / JSON, progress su stderr
│   ├── src/error.rs        # codici di uscita
│   └── tests/              # roundtrip end-to-end sul binario reale
├── src-tauri/              # Tauri backend (bin crate: crypto_tauri)
│   ├── src/
│   │   ├── main.rs         # Tauri commands, AppState, AuditState, tray, updater
│   │   └── audit.rs        # JSONL audit logger
│   ├── capabilities/
│   │   └── default.json    # Tauri permission capabilities
│   └── tauri.conf.json     # App config (finestra, bundle, file assoc., updater)
├── ui/                     # Frontend (HTML + CSS + ES Modules, nessun build step)
│   ├── index.html          # Layout principale, tutti i pannelli
│   ├── styles.css          # Design system con CSS variables dark/light
│   ├── app.js              # Bootstrap: wiring di elementi e moduli
│   ├── loader.js           # Entry point (import dinamico di app.js)
│   └── modules/            # Moduli feature: operations, batch, metadata,
│                           #   history, audit-view, password, dnd, events,
│                           #   theme, tooltip, select, updater, warning,
│                           #   errors, dom, i18n, tauri-bridge, ui-state
├── fuzz/                   # Fuzzing harness (cargo-fuzz)
├── tests/                  # Regressione crittografica, FEC, pause/cancel,
│                           #   compatibilità formato v4 (+ fixtures)
├── scripts/
│   └── check-version.ps1   # Verifica allineamento versioni
├── .github/workflows/      # CI: test/lint/CodeQL + release.yml (build firmate)
├── VERSION                 # Fonte ufficiale della versione
├── CHANGELOG.md
├── IMPLEMENTATION_PLAN.md  # Piano di hardening/refactoring (storico)
├── FORMAT_SPEC.md          # Specifica normativa del formato .ecf (v5)
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
- `ops/Cargo.toml`
- `cli/Cargo.toml`
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

**Segnalazione vulnerabilità**: usare *GitHub → Security → "Report a
vulnerability"* (segnalazione privata) o contattare il maintainer
direttamente. Non pubblicare vulnerabilità come issue pubbliche.

---

## Licenza

Dual license **MIT OR Apache-2.0** — vedere i file `LICENSE-MIT` e
`LICENSE-APACHE` (o `license = "MIT OR Apache-2.0"` nei file `Cargo.toml`).
