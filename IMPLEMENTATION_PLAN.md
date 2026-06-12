# Piano di implementazione — Hardening e refactoring Cryptera

> Documento operativo derivato dalla review completa dell'applicazione (giugno 2026).
> Ogni task è autonomo e committabile separatamente. I riferimenti a file/righe
> sono indicativi rispetto allo stato del codice alla data della review; verificarli
> prima di applicare le modifiche.
>
> **Convenzione commit**: `fix(scope): ...`, `refactor(scope): ...`, `docs: ...`,
> `test: ...` — un commit per task, con riferimento all'ID (es. `[P1-1]`).

---

## Stato di avanzamento

| ID | Task | Priorità | Stato |
|----|------|----------|-------|
| P1-1 | Escape dati attacker-controlled nella UI | Alta | ☑ `a5af03a` |
| P1-2 | Clear password dopo ogni operazione | Alta | ☑ `f09ab60` |
| P1-3 | Correzione README: filename NON cifrato | Alta | ☑ `d4e09a2` |
| P1-4 | Sanitizzazione errori nel log audit | Alta | ☑ `8e33200` |
| P2-1 | Errori strutturati `{code, message}` via IPC | Media | ☑ `673ff6c` |
| P2-2 | Fix race condition in `checkFileMetadata` | Media | ☑ `e582da0` |
| P2-3 | Validazione file batch + fallback directory | Media | ☑ `b018709` |
| P2-4 | `NamedTempFile` nel backend Tauri | Media | ☑ `5d0e243` |
| P2-5 | Fix accessibilità (ARIA, tastiera, live region) | Media | ☑ `325261f` |
| P3-1 | Dedup `decrypt_internal`/`verify_internal` nel core | Bassa | ☑ `c086eec` |
| P3-2 | Split `ui/app.js` in moduli feature | Bassa | ☑ `281cc55` |
| P3-3 | Estrazione struttura comune comandi Tauri | Bassa | ☑ `4f3ac60` |
| P3-4 | Test pause/cancel + formato audit | Bassa | ☑ `fc477d3` |
| P3-5 | Idempotenza setup UI + Condvar per pausa | Bassa | ☑ `5b708d6` |
| P3-6 | Riduzione allocazioni hot loop core | Bassa | ☑ `a8fd728` |
| P3-7 | Allineamento README (compressioni) | Bassa | ☑ verificato: già corretto, nessuna modifica (vedi `d4e09a2`) |
| P4-1 | Formato v5: filename cifrato nell'header | Opzionale | ☑ `9f2b20f` (core), `3e3b593` (UI), `7c7c0b3` (docs), `71fe703` (bump 2.0.0) |

### Note di implementazione (giugno 2026)

- **Ordine**: P2-1 è stato implementato prima di P1-4, che ne dipendeva
  (con gli errori strutturati il logging del solo codice diventa banale).
- **P2-4**: anziché aggiungere `NamedTempFile` nel backend, è stato rimosso
  il livello `.tmp` ridondante — il core scrive già su `NamedTempFile`
  nella directory di destinazione e fa rename atomico (`atomic_replace`).
- **P3-2**: aggiunto `events.js` (listener progress/status) oltre ai moduli
  previsti; `tooltip.js` esporta `attachTooltip` al posto del global
  `window.attachTooltip`.
- **P3-5**: la pausa usa `Condvar` con timeout di sicurezza 200ms;
  `ControlFlags` ora espone `new()/set_pause()/request_cancel()/wait_if_paused()`
  e deriva `Clone`.
- **P3-6**: benchmark informale (100 MB, release, Argon2 ridotto):
  ~1.1s encrypt / ~0.25s decrypt sia prima che dopo — differenza entro il
  rumore di misura; il beneficio è la riduzione della pressione
  sull'allocatore (~4 allocazioni per shard in meno).
- **P3-1**: unica variazione osservabile: il messaggio di verify per
  versione non supportata ora coincide con quello di decrypt
  ("Unsupported version N (max 4)"); codice errore invariato.
- **P4-1 (completato, app 2.0.0 / header v5)**: fixture v4 generate e
  committate PRIMA della modifica al writer (`tests/fixtures/`, commit
  `b32ccff`) con test di compatibilità; record filename nell'header:
  `ct_len(u16) || ct || tag`, nonce riservato `(0xFFFFFFFE, 0xFFFFFFFE)`,
  AAD `ECF1-FNAME-V5`; `read_metadata` senza password mostra segnaposto,
  decrypt/verify restituiscono il nome reale. Key-commitment per il pwchk
  valutato e NON modificato: l'header auth tag (HMAC) è verificato prima
  di ogni record GCM e già vincola il file a una sola chiave.
  `FORMAT_SPEC.md` riscritto per v5 correggendo anche derive pre-esistenti
  rispetto al codice (posizione auth tag, layout shard, AAD, trailer).

Aggiornare questa tabella (☐ → ☑) man mano che i task vengono completati.

---

## FASE 1 — Sicurezza immediata (effort: ~1 giorno)

### P1-1 · Escape dei dati attacker-controlled nella UI

**Problema**: il filename letto dall'header `.ecf` (controllabile da chi ha creato
il file) e i messaggi d'errore vengono interpolati in template string passate a
`innerHTML`. La CSP (`script-src 'self'`, no `unsafe-inline`) blocca l'esecuzione
di script, ma resta possibile iniettare markup e falsificare la UI.

**Punti da correggere in `ui/app.js`**:
- `renderHistory()` (~riga 322-335): `<span class="hi-file">${basename(entry.filename)}</span>`
- `renderBatchList()` (~riga 376-388): `title="${item.path}"` e `${basename(item.path)}`
- Rendering audit log (~riga 489-525): `tbody.innerHTML = \`...${err}...\`` e campi delle entry
- Rendering risultato verify (~riga 339-361): campi `meta` non escapati

**Soluzione**: aggiungere in `ui/modules/ui-state.js` (o nuovo `ui/modules/dom.js`):

```js
export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
```

e applicarla a **ogni** valore dinamico interpolato in `innerHTML`. In alternativa
(preferibile dove il refactoring è poco invasivo) costruire i nodi con
`document.createElement` + `textContent`, come già fa `renderMetaTo()` in
`ui-state.js`.

**Criteri di accettazione**:
- Cifrare un file il cui nome contiene `<img src=x onerror=alert(1)>.txt` e
  `"><b>x</b>`, decifrarlo/verificarlo: storico, batch, audit e meta panel devono
  mostrare il nome letteralmente, senza markup interpretato.
- Nessun uso residuo di `innerHTML` con dati provenienti da header, path o errori
  (`grep -n 'innerHTML' ui/` e verifica manuale di ogni occorrenza).

### P1-2 · Clear delle password dopo ogni operazione

**Problema**: i campi password (`encPassword`, `encPasswordConfirm`, `decPassword`,
`verifyPassword`, `batchPassword`) restano valorizzati nel DOM dopo l'operazione;
vengono puliti solo dal Reset manuale (`handleReset`, `app.js:861-907`).

**Soluzione** in `ui/app.js`:
1. Aggiungere helper `clearPasswordFields(...inputs)` che imposta `value = ""` e
   spegne eventuali toggle "mostra password".
2. Chiamarlo in un blocco `finally` dentro `handleEncrypt` (~726), `handleDecrypt`
   (~769), `handleVerify` (~801) e al termine del batch (~411-486) —
   **solo a operazione conclusa** (successo o errore definitivo), non su
   pausa/annullamento a metà.
3. (Facoltativo, consigliato) timer di auto-clear dopo 5 minuti di inattività
   sui campi password, resettato a ogni `input`.

**Criteri di accettazione**:
- Dopo encrypt/decrypt/verify/batch (sia successo che errore) i campi password
  sono vuoti.
- L'auto-popolamento di altri campi (output path ecc.) non viene toccato.

### P1-3 · Correzione documentazione: il filename NON è cifrato

**Problema**: `README.md` (sezione "Formato dei file `.ecf`") dichiara
"Filename originale (opzionale, **cifrato** in header)", ma in `write_header`
(`src/lib.rs:293-298`) il nome è scritto **in chiaro** nell'header — è solo
autenticato (HMAC v4 / AAD), non cifrato.

**Soluzione**:
- README: sostituire con "Filename originale (opzionale, in chiaro nell'header,
  autenticato)". Aggiungere nota: per nascondere il nome usare l'opzione
  hide-filename (filename vuoto).
- `FORMAT_SPEC.md`: verificare che la descrizione del campo filename sia coerente
  (in chiaro + autenticato); correggere se necessario.
- `SECURITY.md`: aggiungere il filename in chiaro tra le informazioni esposte dal
  formato (metadata leakage), accanto a dimensioni e parametri.

**Criterio di accettazione**: nessun documento afferma che il filename sia cifrato.
La cifratura reale del filename è il task P4-1 (richiede bump formato).

### P1-4 · Sanitizzazione errori nel log di audit

**Problema**: in `src-tauri/src/main.rs` le entry audit includono il messaggio
d'errore verbatim (`error: res.as_ref().err().cloned()`, ~righe 548, 679, 755).
I messaggi del core contengono percorsi e dettagli I/O; il log JSONL è in chiaro
e persistente.

**Soluzione**:
1. Il core espone già codici stabili (`src/lib.rs:79-87`: `PASSWORD_INVALID`,
   `CORRUPT_BEYOND_FEC`, `HEADER_INVALID`, `HEADER_AUTH_FAILED`,
   `PARAMS_OUT_OF_LIMITS`, `TRUNCATED`, `IO_ERROR`, `CANCELLED`, `UNKNOWN_ERROR`).
2. Aggiungere in `main.rs` una funzione `audit_error_code(err: &str) -> String`
   che estrae/normalizza il codice (diventa banale dopo P2-1, quando l'errore
   sarà strutturato; fino ad allora, matchare sul prefisso del codice).
3. Nel log audit scrivere **solo il codice**, mai il messaggio completo.
   Il messaggio dettagliato resta disponibile alla UI per il feedback immediato.

**Criteri di accettazione**:
- Provocare un errore I/O (output su directory inesistente) e uno di password:
  `audit.jsonl` contiene solo il codice (es. `"error":"IO_ERROR"`), nessun path
  oltre al campo `file` già documentato, nessun testo libero.
- Test unit su `audit_error_code` per ogni codice noto + fallback `UNKNOWN_ERROR`.

---

## FASE 2 — Robustezza e UX (effort: 2–3 giorni)

### P2-1 · Errori strutturati `{code, message}` attraverso l'IPC

**Problema**: i comandi Tauri ritornano `Result<_, String>` e il frontend mappa
gli errori con string-matching sul testo (`mapErrorToUserFeedback`,
`app.js:80-103`, ~22 condizioni). Fragile: cambiare un messaggio rompe la UX.

**Soluzione**:
1. In `main.rs` definire:
   ```rust
   #[derive(serde::Serialize)]
   struct CmdError { code: String, message: String }
   ```
   con `From<CoreError>` (il `CoreError` del core ha già `code` + `message`) e
   `From<String>`/helper per gli errori generati nel backend (validazioni, tar,
   I/O) assegnando codici dedicati (`OUTPUT_EXISTS`, `INPUT_NOT_FOUND`,
   `TAR_ERROR`, ...).
2. Cambiare la firma di tutti i comandi in `Result<T, CmdError>` (Tauri
   serializza l'errore come JSON; il frontend lo riceve come oggetto).
3. In `ui/app.js` riscrivere `mapErrorToUserFeedback` come lookup
   `code → chiave i18n` con fallback su `message`. Mantenere temporaneamente il
   vecchio string-matching come fallback per errori non strutturati, da
   rimuovere a fine fase.
4. Aggiornare `i18n.js` (en/it) con le chiavi per ogni codice.

**Criteri di accettazione**:
- Password errata, file corrotto, file troncato, output esistente: la UI mostra
  il messaggio localizzato corretto in IT e EN.
- Nessun `raw.includes("...")` su testo libero residuo per i percorsi coperti
  da codici.

### P2-2 · Fix race condition in `checkFileMetadata`

**Problema** (`app.js:910-946`): selezioni rapide di due file in Decrypt possono
far renderizzare i metadati del file sbagliato e sovrascrivere `decOutput`/
`decExtract` modificati dall'utente.

**Soluzione**: token anti-stale:

```js
let _metaRequestToken = 0;
async function checkFileMetadata(path) {
  const token = ++_metaRequestToken;
  try {
    const meta = await invoke("read_metadata", { req: { input_file: path } });
    if (token !== _metaRequestToken) return; // risposta obsoleta
    // ... rendering e auto-popolamento ...
  } catch (err) {
    if (token !== _metaRequestToken) return;
    // ... gestione errore ...
  }
}
```

Inoltre: auto-popolare `decOutput`/`decExtract` **solo se** l'utente non li ha
già modificati manualmente (flag `dirty` settato su `input`/`change`).

**Criteri di accettazione**: selezionando file A e subito file B, i metadati
mostrati sono di B; i campi modificati a mano non vengono sovrascritti.

### P2-3 · Validazione batch: estensione `.ecf` e directory di output

**Problema** (`app.js:962-996` drag&drop, `app.js:446-449` calcolo directory):
1. Il batch accetta qualsiasi file senza verificare l'estensione.
2. Con path privi di separatore, `substring(0, lastIndexOf(sep))` produce `""`
   → errore criptico dal backend.

**Soluzione**:
```js
const isEcfFile = (p) => /\.ecf$/i.test(p);
```
- Applicarla sia al drag&drop sia al picker; per i file scartati mostrare un
  warning via `setStatus` (nuova chiave i18n `batch_invalid_file`).
- Calcolo directory con fallback sicuro:
  ```js
  const lastSep = item.path.lastIndexOf(sep);
  const dir = batchOutputFolder?.value?.trim()
    || (lastSep > 0 ? item.path.substring(0, lastSep) : ".");
  ```

**Criteri di accettazione**: trascinare un `.txt` nel batch produce un warning e
il file non viene aggiunto; un path relativo senza separatore non genera
`output_path` vuoto.

### P2-4 · `NamedTempFile` per gli output del backend Tauri

**Problema** (`main.rs:501, 609`): il backend usa il path prevedibile
`"{output}.tmp"`, mentre il core usa già `tempfile::NamedTempFile` (vedi
`atomic_replace`, `src/lib.rs:849-871`).

**Soluzione**: sostituire con `NamedTempFile::new_in(parent_dell_output)` +
rename atomico (riusare/esportare `atomic_replace` dal core invece di duplicarlo).
Aggiungere `tempfile` alle dipendenze di `src-tauri/Cargo.toml` se assente.
Verificare che la pulizia avvenga anche su errore/cancellazione (RAII di
`NamedTempFile` la garantisce finché non si fa `persist`).

**Criteri di accettazione**: nessuna occorrenza di `format!("{}.tmp"` in
`src-tauri/`; cancellando un'operazione a metà non restano file temporanei.

### P2-5 · Accessibilità

**Problemi** (`ui/index.html`, `ui/app.js`):
1. `aria-selected` dei tab mai aggiornato al click (`bindNavigation`,
   `app.js:538-552`).
2. `aria-expanded` dei custom select mai aggiornato (`app.js:1131`).
3. Custom select non utilizzabili da tastiera (niente Enter/Space/frecce/Escape).
4. `setStatus` non annuncia gli aggiornamenti agli screen reader.

**Soluzione**:
- In `bindNavigation`: `btn.setAttribute("aria-selected", "true")` sul tab attivo,
  `"false"` sugli altri.
- Nei custom select: sincronizzare `aria-expanded` con la classe `open`; gestire
  `keydown` su trigger (Enter/Space apre, Escape chiude, frecce navigano le
  option, Enter seleziona); `tabindex="0"` dove manca.
- Sul nodo di stato: `role="status"` + `aria-live="polite"` (statico in
  `index.html`, una sola volta).

**Criteri di accettazione**: navigazione completa tab + select con sola tastiera;
attributi ARIA coerenti con lo stato visivo a ogni interazione.

---

## FASE 3 — Refactoring e debito tecnico (effort: ~1 settimana)

> Ordine consigliato: P3-1 e P3-3 prima di P3-4 (i test si scrivono sul codice
> già rifattorizzato); P3-2 indipendente.

### P3-1 · Deduplicazione `decrypt_internal` / `verify_internal` nel core

**Problema**: `decrypt_internal_rs_controlled` (`src/lib.rs:1381-1611`) e
`verify_internal_rs_controlled` (`src/lib.rs:1613-1784`) condividono ~170 righe
quasi identiche: apertura header, validazione, KDF, header auth, password check
record, loop blocchi (CRC → GCM → FEC).

**Soluzione**:
1. Estrarre `fn open_and_authenticate(input, password, keyfile_hash) ->
   Result<(HeaderParams, Vec<u8> /*prefix*/, Aes256Gcm, u64 /*data_offset*/), CoreError>`
   che copre header, limiti, KDF, header auth e pwchk.
2. Estrarre `fn process_blocks(f_in, params, prefix, cipher, g, sink:
   Option<&mut dyn Write>, control, progress, stage: &str) -> Result<(), CoreError>`:
   con `sink = Some(writer)` decifra e scrive (decrypt), con `sink = None` si
   limita ad autenticare/ricostruire (verify).
3. `decrypt_internal` mantiene in esclusiva: setup `LimitedWriter` +
   decompressore, `atomic_replace` finale.

**Vincoli**: nessun cambiamento di comportamento osservabile — stessi codici
d'errore, stessi messaggi, stesso ordine di validazione (limiti **prima** della
KDF). I test esistenti (`tests/core_roundtrip.rs`, `tests/security_auto.rs`) e
il fuzzing devono passare invariati.

**Criteri di accettazione**: `cargo test` e `cargo clippy -- -D warnings` verdi;
diff netto negativo di almeno ~120 righe in `src/lib.rs`; roundtrip
encrypt→verify→decrypt su file con corruzione artificiale entro/oltre il budget
FEC dà gli stessi esiti di prima del refactoring.

### P3-2 · Split di `ui/app.js` in moduli feature

**Problema**: `app.js` ~1230 righe con responsabilità miste (operazioni, batch,
tema, tooltip, select, audit, history, i18n, boot).

**Struttura target**:
```
ui/modules/
  dom.js          # escapeHtml, helper creazione nodi (da P1-1)
  errors.js       # mapErrorToUserFeedback su codici (da P2-1)
  password.js     # strength meter, policy, clearPasswordFields (app.js:130-208)
  history.js      # ring buffer + renderHistory (app.js:279-336)
  batch.js        # stato, rendering, run batch (app.js:364-486)
  audit-view.js   # rendering tab audit (app.js:489-525)
  operations.js   # handleEncrypt/Decrypt/Verify/Reset (app.js:726-907)
  metadata.js     # checkFileMetadata + token anti-stale (app.js:910-946)
  dnd.js          # drag&drop (app.js:962-1036)
  theme.js        # tema + localStorage (app.js:232-276)
  tooltip.js      # tooltip (app.js:1039-1083)
  select.js       # custom select + tastiera (app.js:1114-1151)
app.js            # solo bootstrap: import, bind navigazione, init
```

**Regole**: nessun cambiamento funzionale contestuale allo split (i fix sono nei
task dedicati); niente bundler — restano ES Modules nativi; un commit per
modulo estratto o per gruppi coesi, così ogni step è verificabile con
`cargo tauri dev`.

**Criteri di accettazione**: `app.js` ridotto a < 250 righe di bootstrap; app
funzionante (encrypt/decrypt/verify/batch/audit/tema/lingua) dopo ogni commit.

### P3-3 · Estrazione struttura comune dei comandi Tauri

**Problema**: `encrypt` (~`main.rs:400-555`), `decrypt` (~558-686), `verify`
(~689-762) ripetono lo stesso scheletro: validazione → ControlFlags → 
`spawn_blocking` → emit status/progress → chiamata core → entry audit → cleanup.

**Soluzione**: helper
```rust
async fn run_operation<T: Send + 'static>(
    window: tauri::Window,
    state: tauri::State<'_, AppState>,
    audit: tauri::State<'_, AuditState>,
    op_name: &'static str,
    input_path: String,
    job: impl FnOnce(ControlFlags, ProgressEmitter) -> Result<T, CmdError> + Send + 'static,
) -> Result<T, CmdError>
```
che incapsula flags, spawn_blocking, emissione eventi, audit (con codice
sanitizzato da P1-4) e cleanup. I tre comandi diventano composizioni della
propria logica specifica (tar per le cartelle, estrazione post-decrypt, ecc.).

**Criteri di accettazione**: comportamento invariato (eventi `progress`/`status`
con stesso payload, stesse entry audit); test esistenti verdi; eliminata la
triplicazione del blocco flags/spawn/audit.

### P3-4 · Test mancanti

Aggiungere (in `src-tauri/src/main.rs` `#[cfg(test)]` o `tests/`):
1. **Pause/cancel**: avviare encrypt su file multi-blocco con `ControlFlags`,
   settare `pause` → verificare che il progresso si fermi; settare `cancel`
   durante la pausa → errore `CANCELLED` e nessun file di output residuo.
2. **Formato audit**: scrivere entry con errori contenenti caratteri speciali e
   path unicode → ogni riga del JSONL deve essere JSON valido e l'errore deve
   essere solo un codice (P1-4).
3. **Edge case tar**: cartella il cui nome contiene caratteri non-UTF8 (ove
   possibile) e cartella radice (`file_name() == None`, `main.rs:230-233`) →
   nome archivio di fallback sensato (es. `archive.tar`), non `.tar`.
4. **Core**: roundtrip con corruzione mirata di r shard (recuperabile) e r+1
   shard (errore `CORRUPT_BEYOND_FEC`) se non già coperto in
   `tests/security_auto.rs` — verificare ed eventualmente integrare.

### P3-5 · Micro-fix di qualità

- **Idempotenza setup UI**: guardie `let done = false` per `setupTooltips()` e
  `setupCustomSelects()` (`app.js:1069-1151`), come già fatto per
  `bindProgressEvents`.
- **Pausa senza busy-wait**: sostituire il loop `sleep(50ms)` (`main.rs:258-263`
  e `control_wait` in `src/lib.rs:396-409`) con `Condvar` + `Mutex<bool>` in
  `ControlFlags` (`notify_all` su resume/cancel). Attenzione: `ControlFlags` è
  condiviso col core → modificare la struct in `src/lib.rs` e propagare.
- **Magic numbers UI**: costanti nominate per i flag header usati nel frontend
  (`const META_FLAG_TAR_CONTAINER = 0x20` ecc., oggi `meta.flags & 32` in
  `app.js`), allineate ai valori di `src/lib.rs:66-70`.

### P3-6 · Riduzione allocazioni nel loop shard del core

**Problema**: per ogni shard vengono allocati `[ct_body, tag].concat()` (encrypt,
`src/lib.rs:1242`; CRC check in decrypt/verify, righe ~1544/1744) e l'AAD
`[prefix, block_be, shard_be].concat()` (righe ~1226-1231, ~1549-1554). Su file
grandi sono milioni di allocazioni evitabili.

**Soluzione**:
- CRC senza concat: `hasher.update(ct); hasher.update(tag); hasher.finalize()`
  (CRC32 è streaming, il risultato è identico).
- AAD: buffer riusabile pre-allocato fuori dal loop (`aad_buf.truncate(prefix.len());
  aad_buf.extend_from_slice(...)`) — il prefisso è costante, cambiano solo gli
  8 byte finali.
- Buffer `data` (ct+tag) riusabile allo stesso modo.

**Criteri di accettazione**: output binario identico byte-per-byte a parità di
input/parametri/salt/nonce (verificabile con test deterministico che fissa il
contenuto e confronta il roundtrip); benchmark informale prima/dopo su file
~100 MB annotato nel commit message.

### P3-7 · Allineamento README sulle compressioni

La tabella caratteristiche cita "archivi: gzip / bzip2 / xz" ma il codice supporta
zlib/xz (lzma) pre-cifratura e archiviazione TAR non compressa nel backend.
Aggiornare la riga "Compressione" del README (ed eventuali ripetizioni in
`FORMAT_SPEC.md`) allo stato reale del codice.

---

## FASE 4 — Evoluzione del formato (opzionale, richiede bump a v5)

### P4-1 · Filename cifrato nell'header

**Obiettivo**: rendere vera la garanzia di privacy sul nome file (vedi P1-3).

**Design proposto** (da raffinare in una sessione dedicata):
- Nuovo flag `HDR_FLAG_ENC_FILENAME` (es. `0x40`).
- Il filename non compare più in chiaro nell'header: al suo posto un record
  `enc_fname_len (u16) || ciphertext || tag`, cifrato con AES-256-GCM, nonce
  riservato `nonce12(nonce_base, 0xFFFFFFFE, 0xFFFFFFFE)` (verificare assenza di
  collisioni con i nonce dati e col pwchk `0xFFFFFFFF/0xFFFFFFFF`; i blocchi dati
  sono limitati da `MAX_BLOCKS_U32`), AAD = prefix header + contesto dedicato.
- **Conseguenza**: il filename diventa leggibile solo *dopo* la KDF → 
  `read_metadata` senza password non può più mostrarlo. La UI deve gestire il
  caso "filename disponibile solo dopo decrypt/verify" (mostrare placeholder).
- Compatibilità: lettura v1–v4 invariata; scrittura sempre v5; `VERSION_U8 = 5`;
  bump **MAJOR** della versione applicativa (breaking change del formato, come
  da policy nel README); aggiornare `FORMAT_SPEC.md`, `SECURITY.md`, fuzzing
  corpus e test di compatibilità con file v4 generati prima della modifica.
- Valutare nello stesso bump: spostare il pwchk record su un costrutto
  key-commitment (mitiga anche attacchi multi-key su GCM).

**Prerequisiti**: Fasi 1–3 completate; generare e salvare in `tests/fixtures/`
file `.ecf` v4 di riferimento PRIMA di toccare il writer.

---

## Verifica trasversale (da eseguire a fine di ogni fase)

```bash
cargo test                                          # test core
cargo test --manifest-path src-tauri/Cargo.toml     # test backend
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo deny check                                    # licenze/advisory
pwsh ./scripts/check-version.ps1                    # allineamento versioni
```

Più smoke test manuale con `cargo tauri dev`: encrypt file, encrypt cartella,
decrypt, verify, batch con un file valido + uno corrotto, cambio lingua/tema,
tray hide/restore.

## Note di rilascio

- Fasi 1–2: bump **PATCH** (fix) o **MINOR** se si considera il contratto errori
  IPC una feature; nessun impatto sul formato `.ecf`.
- Fase 3: bump **PATCH** (refactoring senza cambi osservabili).
- Fase 4: bump **MAJOR** (formato v5).
- Aggiornare `CHANGELOG.md` a ogni fase; seguire `RELEASE.md` per i rilasci.
