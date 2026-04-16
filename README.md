# Merkle-Proof Distributed Ledger for Compliance

Un sistema di logging crittografico enterprise che dimostra a un auditor esterno l'integrità e immutabilità dei dati di compliance aziendali negli ultimi 12 mesi, senza esporre i dati sensibili.

## 🎯 Il Problema

Le aziende devono dimostrare agli auditor che i loro dati di compliance (audit log, decisioni, transazioni) non sono stati manipolati retroattivamente. Tuttavia:

- Non si vuole esporre **tutti i dati sensibili** all'auditor
- Il volume può essere enorme (milioni di eventi al mese)
- La verifica deve essere **matematicamente inoppugnabile**

## 💡 La Soluzione

Un **Merkle Tree distribuito** salvato in PostgreSQL che:

1. **Hash dei singoli eventi**: ogni evento è hashato (SHA-256)
2. **Merkle root orario**: ogni ora, gli hash dei 3600 secondi precedenti forme un albero
3. **Firma crittografica**: il root orario è firmato con Ed25519
4. **Inclusion Proof**: dato un evento, genera un certificato matematico di appartenenza senza divulgare altri eventi

### Caso d'uso concreto

Un'azienda finanziaria deve provare che una transazione di compliance avvenuta il 2 marzo 2025 alle 14:32 non è stata alterata. L'auditor richiede:

- La prova che quella transazione era nel sistema
- La firma crittografica del blocco orario
- **Non vuole** vedere tutti gli altri 3599 eventi dell'ora

Questo sistema genera esattamente quella prova, in ~32 bytes di dati auditabili.

## 🏗️ Architettura

```
┌─────────────────────────────────────────────────────┐
│  PostgreSQL Database                                 │
├─────────────────────────────────────────────────────┤
│                                                      │
│  compliance_event table                             │
│  ├─ event_id (PK)                                   │
│  ├─ occurred_at (TIMESTAMPTZ)                       │
│  ├─ payload (JSONB - dati sensibili)                │
│  └─ event_hash (BYTEA - SHA256)                     │
│                                                      │
│  hourly_root table                                  │
│  ├─ hour_start (PK)                                 │
│  ├─ root_hash (BYTEA - radice Merkle)              │
│  ├─ signature (BYTEA - Ed25519)                     │
│  └─ signed_at (TIMESTAMPTZ)                         │
│                                                      │
└─────────────────────────────────────────────────────┘
         ↑           ↑           ↑
         │           │           │
    ingest-event  finalize-hour  prove-event
         │           │           │
         └───────────┴───────────┘
            Node.js CLI

                 ↓
         verifySignature()
         verifyMerkleProof()
         (offline, nessun DB)
```

## 🔐 Concetti chiave

### 1. SHA-256 Hashing
Ogni evento viene serializzato in JSON (con ordinamento stabile delle chiavi) e hashato:

```javascript
const eventHash = sha256(JSON.stringify(payload))
// Produce: 64 caratteri hex, 32 bytes
// Deterministico: stesso payload = stesso hash sempre
```

### 2. Merkle Tree
Albero binario di hash che comprime N eventi in 1 root:

```
                Root (32 bytes)
               /              \
           Parent1           Parent2
           /      \          /      \
         H1      H2        H3      H4
        /  \    /  \      /  \    /  \
       E1  E2  E3  E4    E5  E6  E7  E8

Proprietà:
- Se un evento cambia, il root cambia
- Non serve memorizzare tutto l'albero, solo il root
- Prova di inclusione: O(log N) dati
```

### 3. Inclusion Proof
Certificato che un evento appartiene al root senza rivelar altri eventi:

```json
{
  "event_id": 42,
  "hour_start": "2025-04-15T14:00:00Z",
  "event_hash": "abc123...",
  "root_hash": "def456...",
  "signature": "xyz789...",
  "proof": [
    { "sibling": "h1hash", "position": "right" },
    { "sibling": "h2hash", "position": "left" }
  ]
}
```

## 📦 Installazione

### Prerequisiti

- **Node.js** >= 18.0.0
- **PostgreSQL** >= 12
- npm

### Step 1: Clona e installa dipendenze

```bash
cd /path/to/data-integrity
npm install
```

### Step 2: Prepara PostgreSQL

```bash
createdb merkle_compliance
```

Aggiorna il tuo `.env` o DSN:

```bash
export MERKLE_DSN="postgresql://user:password@localhost:5432/merkle_compliance"
```

### Step 3: Inizializza il database

```bash
merkle-proof init-db --dsn "$MERKLE_DSN"
```

Output:
```
Database inizializzato. Chiave pubblica: AbCdEfGhIjKlMnOpQrStUvWxYz...
```

Le chiavi Ed25519 sono salvate in `keys/` (gitignore).

## 🚀 Uso

### 1. Ingestione di un evento

```bash
merkle-proof ingest-event \
  --dsn "$MERKLE_DSN" \
  --payload '{"user":"alice","action":"login","amount":1000}' \
  --occurred-at "2025-04-15T14:32:45Z"
```

Output:
```
Evento inserito con event_id=1 alle 2025-04-15T14:32:45.000Z
```

**Più eventi (loop di test):**

```bash
for i in {1..100}; do
  merkle-proof ingest-event \
    --dsn "$MERKLE_DSN" \
    --payload "{\"transaction_id\":$i,\"amount\":$(($RANDOM % 10000))}"
done
```

### 2. Finalizzazione del root orario

Alla fine di ogni ora, il sistema deve calcolare e firmare il Merkle root:

```bash
merkle-proof finalize-hour \
  --dsn "$MERKLE_DSN" \
  --hour-start "2025-04-15T14:00:00Z"
```

Output:
```
Root orario salvato per 2025-04-15T14:00:00.000Z
root_hash=a1b2c3d4e5f6...
```

**Automazione con cron (Linux/macOS):**

```bash
# Ogni ora, all'inizio
0 * * * * /usr/local/bin/merkle-proof finalize-hour --dsn "$MERKLE_DSN" --hour-start "$(date -u +'%Y-%m-%dT%H:00:00Z')"
```

**Automazione con Windows Task Scheduler:**

```powershell
# Crea un task ogni ora
$script = @"
$env:MERKLE_DSN="postgresql://user:pass@localhost/merkle_compliance"
merkle-proof finalize-hour --dsn $env:MERKLE_DSN --hour-start (Get-Date -AsUTC -Format "yyyy-MM-ddTHH:00:00Z")
"@
$script | Out-File C:\scripts\finalize.ps1
```

### 3. Generazione della prova di inclusione

Un auditor richiede: "Provami che l'evento 42 era nel sistema il 15 aprile 2025 alle 14:00 UTC".

```bash
merkle-proof prove-event \
  --dsn "$MERKLE_DSN" \
  --event-id 42 \
  --hour-start "2025-04-15T14:00:00Z" > proof.json
```

`proof.json`:
```json
{
  "event_id": 42,
  "hour_start": "2025-04-15T14:00:00Z",
  "event_hash": "abc123...",
  "root_hash": "def456...",
  "signature": "xyz789...",
  "proof": [
    { "sibling": "h1", "position": "right" },
    { "sibling": "h2", "position": "left" }
  ]
}
```

### 4. Verifica della prova (offline, without DB)

L'auditor può verificare la prova **senza accesso al database**:

```bash
merkle-proof verify-proof \
  --event-hash "abc123..." \
  --proof-file proof.json \
  --public-key keys/public_key.pem
```

Output:
```
Merkle proof valida: true
Firma del root valida: true
```

**Verifica in JavaScript (programmatica):**

```javascript
import { verifyMerkleProof } from 'data-integrity-ledger';
import { verifySignature } from 'data-integrity-ledger';

const eventHash = Buffer.from('abc123...', 'hex');
const proof = [
  { sibling: Buffer.from('h1', 'hex'), position: 'right' },
  { sibling: Buffer.from('h2', 'hex'), position: 'left' }
];
const root = Buffer.from('def456...', 'hex');
const isValid = verifyMerkleProof(eventHash, proof, root);
// true/false
```

## 📊 Prestazioni e Scalabilità

### Complessità temporale

| Operazione | Complessità | Tempo tipico |
|-----------|-----------|------------|
| Inserimento evento | O(1) | 1-5 ms |
| Calcolo root (3600 eventi) | O(n) | 100-200 ms |
| Generazione prova | O(log n) | 10-20 ms |
| Verifica prova | O(log n) | 5-10 ms |

### Scalabilità

- **10k eventi/min**: ~6 milioni/anno, facile per una singola istanza PostgreSQL
- **100k eventi/min**: ~52 milioni/anno, considerare read replicas
- **1M+ eventi/min**: sharding orizzontale, Merkle Tree distribuito

## 🧪 Test

```bash
npm test
```

Output:
```
TAP version 13
ok 1 - sha256 hash is stable
ok 2 - build merkle root for single leaf
ok 3 - build merkle root for multiple leaves
ok 4 - inclusion proof verifies correctly
ok 5 - signer creates keypair and verifies signature

# tests 5
# pass 5
# fail 0
```

## 📁 Struttura del progetto

```
data-integrity/
├── src/
│   ├── cli.js              # Command-line interface
│   ├── db.js               # DatabaseClient, query PostgreSQL
│   ├── merkle.js           # Merkle Tree, inclusion proof, verifica
│   ├── signer.js           # KeyManager, firma Ed25519
│   └── index.js            # Esportazioni pubbliche
├── migrations/
│   └── setup.sql           # Schema PostgreSQL
├── tests/
│   ├── test_merkle.test.js # Test Merkle Tree
│   └── test_signer.test.js # Test firma digitale
├── keys/
│   ├── private_key.pem     # Ed25519 privata (gitignore)
│   └── public_key.pem      # Ed25519 pubblica
├── package.json
├── package-lock.json
├── README.md               # Questo file
├── COMPETENCIES.md         # Competenze richieste
└── .gitignore
```

## 🔑 Gestione delle chiavi

### Generazione automatica

Al primo `init-db`, la CLI genera una coppia Ed25519:

```bash
merkle-proof init-db --dsn "..." --key-dir /secure/location
```

La chiave privata è salvata in PEM formato, non crittografata. **Proteggila con permessi del file system**:

```bash
chmod 600 keys/private_key.pem
# Accesso solo propriètario
```

### Backup e rotazione

```bash
# Backup della chiave pubblica (condividi con auditor)
cp keys/public_key.pem audit_public_key_2025_04.pem

# Rotazione (crea nuova coppia, migra dati)
merkle-proof init-db --dsn "..." --key-dir keys_new
# Manualmente aggiorna records
# UPDATE hourly_root SET re_sign = true WHERE hour_start >= '2025-05-01';
```

## 🛡️ Sicurezza

### Threat Model

| Minaccia | Mitigazione |
|----------|------------|
| Evento alterato nel DB | Cambierebbe l'event_hash, root non matcherebbe firma |
| Evento inserito in mezzo | Cambierebbe l'indice nel Merkle Tree, inclusione proof falserebbe |
| Firma falsificata | Ed25519 is post-quantum safe, infeasible brute-force |
| Replica di una prova vecchia | Auditor verifica timestamp, context specifico |
| Compromesso chiave privata | Generate nuova coppia, re-sign tutte le ore future |

### Best Practices

1. **Separa i secret**: Usa Vault/Secrets Manager per DSN e chiave privata
2. **Audit accessi DB**: Log tutti gli INSERT/UPDATE su compliance_event
3. **Snapshot pubblici**: Esporta chiavi pubbliche periodicamente, commit in Git
4. **Test di penetration**: Verifica che un attaccante DB non possa falsificare

## 🤝 Contribuire

Le pull request sono benvenute! Per cambiamenti sostanziali:

1. **Fork** il repository
2. Crea un branch (`feature/my-feature`)
3. Scrivi test per la nuova logica
4. Submitt PR con descrizione

## 📄 Licenza

MIT License - vedi LICENSE per dettagli

## ❓ FAQ

**Q: Quanto tempo una prova rimane valida?**  
A: Indefinitamente, se:
- Il pubblico ternary (public_key.pem) rimane verificato
- La firma del root è intatta
- L'evento non è stato alterato

**Q: Cosa succede se il database va down?**  
A: Gli eventi recenti non sono firmati. Una volta ripristinato:
1. Inserisci gli eventi mancanti
2. Esegui `finalize-hour` per il periodo interessato
3. Le prove passate rimangono valide

**Q: Posso usarlo per blockchain?**  
A: No, usa una blockchain vera. Questo è un sistema di auditabilità, non decentralizzato.

**Q: Performance su milioni di righe?**  
A: PostgreSQL scale bene. Usa indici su occurred_at e event_hash. Considera partitioning per anni.

**Q: Posso cambiare il payload dopo l'evento?**  
No, il payload è immutabile (hashato). Inserisci un nuovo evento di correzione.

## 📞 Supporto

- 📖 Documentazione: Vedi COMPETENCIES.md
- 🐛 Bug report: GitHub Issues
- 💬 Discussioni: GitHub Discussions

---

**Last updated**: April 15, 2026  
**Project version**: 0.1.0  
**Node.js**: >= 18.0.0  
**PostgreSQL**: >= 12

