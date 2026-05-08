# CryptoV2

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/crypto-AES--256--GCM-brightgreen)

Applicazione desktop per la **cifratura sicura di file e cartelle**, con interfaccia grafica moderna e algoritmi crittografici di livello professionale.

---

## Caratteristiche principali

- **AES-256-GCM** — cifratura autenticata con chiave a 256 bit
- **Argon2id** — derivazione della chiave resistente ad attacchi GPU/ASIC
- **Reed-Solomon FEC** — correzione errori che permette il recupero dati anche su file corrotti
- **Header ridondante** — copia dell'intestazione in fondo al file per il recupero in caso di corruzione parziale
- **Compressione opzionale** — zlib o lzma prima della cifratura
- **Keyfile** — autenticazione a due fattori (password + file segreto)
- **Drag & Drop** — trascina file o cartelle direttamente sulla finestra
- **Batch Decrypt** — decifra più file `.ecf` in una sola operazione
- **Verifica Integrità** — controlla l'autenticità senza decifrar il contenuto
- **Storico Operazioni** — registro delle ultime operazioni nella sessione corrente
- **Dark / Light Mode** — tema adattabile alle preferenze dell'utente
- **Indicatore forza password** — feedback in tempo reale sulla robustezza della password
- **System Tray** — minimizza nell'area di notifica e rimane disponibile in background

---

## Requisiti

- Python 3.11+
- Dipendenze elencate in `requirements.txt`

---

## Installazione

```bash
# Clona il repository
git clone https://github.com/tuo-username/cryptov2.git
cd cryptov2

# Installa le dipendenze
pip install -r requirements.txt

# Avvia l'applicazione
python main_gui.py
```

---

## Utilizzo

### Cifratura file singolo

1. Tab **Encrypt** → seleziona un file (o trascinalo sulla finestra)
2. Scegli un profilo di sicurezza (Standard / Strong / Paranoid)
3. Scegli un profilo di integrità (Low / Medium / High / Max)
4. Opzionale: abilita keyfile per l'autenticazione a due fattori
5. Clicca **Encrypt File** e inserisci la password

### Cifratura cartella

1. Tab **Encrypt** → seleziona una cartella
2. La cartella viene archiviata come TAR e poi cifrata
3. La password di un file cifrato è richiesta al momento dell'operazione

### Decifratura

1. Tab **Decrypt** → seleziona il file `.ecf`
2. Clicca **Decrypt to File** per ottenere il file originale
3. Clicca **Decrypt & Extract** per estrarre direttamente una cartella cifrata

### Batch Decrypt

1. Tab **Batch** → aggiungi più file `.ecf`
2. Clicca **Avvia Batch Decrypt** e inserisci la password una sola volta
3. A fine operazione viene mostrato il riepilogo (successi / errori)

### Verifica Integrità

1. Tab **Decrypt** → seleziona il file `.ecf`
2. Clicca **Verifica Integrità**: controlla header, tag GCM e CRC senza scrivere output
3. Il risultato mostra lo stato del file e i parametri crittografici usati

---

## Profili di sicurezza (Argon2id)

| Profilo  | t (iterazioni) | Memoria | Parallelismo | Uso consigliato |
|----------|:--------------:|:-------:|:------------:|-----------------|
| Standard | 3              | 64 MiB  | 2            | Uso quotidiano  |
| Strong   | 6              | 256 MiB | 4            | Dati sensibili  |
| Paranoid | 10             | 512 MiB | 8            | Massima sicurezza |

## Profili di integrità (Reed-Solomon)

| Profilo | k  | r  | Overhead | Shards recuperabili |
|---------|:--:|:--:|:--------:|---------------------|
| Low     | 28 | 4  | ~14%     | 4 per blocco        |
| Medium  | 24 | 8  | ~33%     | 8 per blocco        |
| High    | 12 | 12 | ~100%    | 12 per blocco       |
| Max     | 8  | 24 | ~300%    | 24 per blocco       |

---

## Formato file `.ecf`

```
[HEADER]   — magic, parametri KDF, salt, nonce_base, k/r, versione, nome file
[PWCHK]    — (opzionale) record per verifica rapida password errata
[BLOCCHI]  — (k+r) shard per blocco, ciascuno AES-256-GCM
[TRAILER]  — copia dell'header per recupero in caso di corruzione
```

---

## Garanzie di sicurezza

| Proprietà          | Meccanismo                                      |
|--------------------|-------------------------------------------------|
| Confidenzialità    | AES-256-GCM (keyspace 2²⁵⁶)                   |
| Integrità          | Tag GCM (128 bit) + CRC duplicato per shard    |
| Autenticazione     | Argon2id con salt casuale a 128 bit             |
| Robustezza fisica  | Reed-Solomon FEC configurabile                  |
| Atomicità scrittura| `os.replace()` — nessun file parziale in caso di crash |

**Fuori scope:** attacchi side-channel, forward secrecy, privacy metadati (dimensione e parametri sono visibili nell'header).

---

## Test

```bash
# Suite completa
pytest tests/ -v

# Con report copertura
pytest tests/ -v --cov=crypto_core --cov-report=term-missing
```

---

## Struttura progetto

```
cryptov2/
├── crypto_core/          # Libreria crittografica
│   ├── __init__.py       # API pubblica: encrypt_file, decrypt_file, decrypt_file_ex, verify_file
│   ├── cipher.py         # Logica principale cifratura/decifratura
│   ├── constants.py      # Costanti, profili, codici errore
│   ├── galois.py         # Aritmetica GF(256) e Reed-Solomon
│   └── header.py         # Serializzazione header file
├── main_gui.py           # Applicazione desktop (CustomTkinter)
├── tests/
│   ├── test_crypto.py    # Test unitari e di integrazione
│   ├── test_fuzzing.py   # Test fuzzing e casi limite
│   └── test_large_files.py # Test su file di grandi dimensioni
├── requirements.txt
└── README.md
```
