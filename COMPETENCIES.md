# Competenze richieste per il progetto Merkle-Proof Distributed Ledger

## 1. Crittografia applicata
- Hashing deterministico dei dati (SHA-256)
- Costruzione e navigazione di Merkle Tree
- Digitally signing data: Ed25519
- Verifica di firme e proof di inclusione
- Gestione sicura di chiavi private/pubbliche

## 2. Database e performance PostgreSQL
- Modellazione schemi per eventi e root orari
- Indici per query temporali e hash
- Inserimento batch e recupero per intervalli orari
- Coerenza dei dati e immutabilità logica
- Uso di `jsonb` per payload sensibili con hashing esterno

## 3. Data integrity e auditability
- Proof of inclusion per mostrare solo ciò che serve
- Separazione fra dati sensibili e metadati verificabili
- Registrazione di root firmati per audit esterno
- Conservazione dei root per effettive non-repudations

## 4. Ingegneria del software
- Progettazione CLI user-friendly
- Test unitari per Merkle Tree e firma digitale
- Documentazione del flusso e dei comandi
- Packaging Python e installazione locale
