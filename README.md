# 🔍 Forensic-Excavator

## 📋 Descrizione
Fase Beta: Forensic-Excavator è uno strumento completo e avanzato per l'acquisizione forense di informazioni di siti web e l'analisi OSINT (Open Source Intelligence). Questo tool integra numerose funzionalità per raccogliere informazioni dettagliate su siti web, domini e infrastrutture digitali, pensato per periti incaricati, utile per la ricerca di informazioni nei siti web, in modo automatico, con report in vari formati.

CREA LA CARTELLA " osint_results " PRIMA DI ESEGUIRE IL TOOL

## 🚀 Caratteristiche avanzate
Risoluzione "dimostra di non essere un robot" CAPTCHA

### 📊 Analisi di Base
- **Estrazione Metadati**: Title, meta description, keywords, headers HTTP
- **Informazioni Server**: Tipo di server, tecnologie utilizzate, cookies
- **Analisi Contenuto**: Dimensione, tipo di contenuto, encoding

### 🌍 Geolocalizzazione e IP
- **Risoluzione IP**: Identificazione dell'indirizzo IP del server
- **Geolocalizzazione**: Paese, regione, città, coordinate GPS
- **Informazioni ISP**: Provider, organizzazione, timezone

### 🔍 Analisi DNS e WHOIS
- **Record DNS Completi**: A, AAAA, MX, NS, TXT, CNAME, SOA
- **Informazioni WHOIS**: Registrar, date di creazione/scadenza, nameserver
- **Analisi Dominio**: Status, email di contatto, paese di registrazione

### ⚙️ Rilevamento Tecnologie
- **Framework Web**: Identificazione CMS, framework, librerie
- **Linguaggi di Programmazione**: Backend e frontend technologies
- **Servizi Cloud**: CDN, hosting provider, servizi esterni

*nota bene: la risoluzione degli IP CDN o il reverse non è attendibile al 100%, non utilizzarlo per prove a carattere forense* 

### 🔎 Enumerazione Sottodomini
- **Ricerca Automatica**: Enumerazione di sottodomini comuni
- **Verifica Attiva**: Controllo della risoluzione DNS
- **Threading**: Ricerca parallela per maggiore velocità

### 🔒 Analisi Sicurezza
- **Certificati SSL**: Dettagli del certificato, validità, issuer
- **Header di Sicurezza**: HSTS, CSP, X-Frame-Options, etc.
- **Valutazione Sicurezza**: Score di sicurezza basato su best practices

### 🕷️ Web Scraping Avanzato
- **Estrazione Link**: Link interni ed esterni
- **Analisi Form**: Form di contatto, login, ricerca
- **Risorse Multimediali**: Immagini, script, fogli di stile
- **Contatti**: Email, numeri di telefono automaticamente estratti
- **Social Media**: Link a profili social automaticamente rilevati

### 📸 Acquisizione Forense
- **Screenshot**: Cattura visiva della pagina web
- **Hash del Contenuto**: MD5, SHA1, SHA256 per integrità
- **Timestamp**: Marcatura temporale di tutte le operazioni

### 📄 Reporting
- **Report JSON**: Dati strutturati per analisi programmatica
- **Report HTML**: Visualizzazione user-friendly dei risultati
- **Organizzazione File**: Struttura ordinata dei risultati

## 🛠️ Installazione

### Prerequisiti
- Python 3.7 o superiore
- Google Chrome (per screenshot)
- Connessione internet

### Installazione Automatica
Lo strumento include un sistema di installazione automatica delle dipendenze:

```bash
# Clona o scarica il progetto
git clone https://github.com/MrL-sec/-Forensic-Excavator---Strumento-Forense-Avanzato.git
cd P\ Osint

# Esegui lo strumento (installerà automaticamente le dipendenze)
python3 osint_web_analyzer.py
```

### Installazione Manuale (Opzionale)
Se preferisci installare manualmente le dipendenze:

```bash
pip3 install -r requirements.txt
```

## 🎯 Utilizzo

### Utilizzo Base
```bash
python3 osint_web_analyzer.py
```

Lo strumento ti chiederà di inserire l'URL o dominio da analizzare:
```
🎯 Inserisci l'URL o dominio da analizzare: example.com
```

### Formati URL Supportati
- `example.com`
- `www.example.com`
- `https://example.com`
- `http://example.com`
- `https://www.example.com/path`

## 📁 Struttura Output

I risultati vengono salvati nella directory `osint_results/`:

```
osint_results/
├── osint_analysis_example.com_20231201_143022.json
├── osint_report_example.com_20231201_143022.html
└── screenshot_example.com.png
```

### File di Output

1. **JSON Report** (`osint_analysis_*.json`)
   - Dati strutturati completi
   - Formato machine-readable
   - Tutti i risultati delle analisi

2. **HTML Report** (`osint_report_*.html`)
   - Visualizzazione user-friendly
   - Formattazione professionale
   - Facile da condividere

3. **Screenshot** (`screenshot_*.png`)
   - Cattura visiva del sito
   - Risoluzione 1920x1080
   - Formato PNG

## 🔧 Configurazione Avanzata

### Personalizzazione Headers
Puoi modificare gli headers HTTP nel codice:

```python
self.headers = {
    'User-Agent': 'Il tuo User-Agent personalizzato',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
}
```

### Timeout e Retry
Configura timeout per le richieste:

```python
response = requests.get(url, headers=self.headers, timeout=30)
```

### Sottodomini Personalizzati
Aggiungi sottodomini alla lista di ricerca:

```python
common_subdomains = [
    'www', 'mail', 'ftp', 'admin', 'test', 'dev',
    'tuo-sottodominio-personalizzato'
]
```

## 🛡️ Considerazioni Legali ed Etiche

### ⚖️ Uso Legale
- Utilizza questo strumento solo su domini di tua proprietà, o su domini in cui si dispone del diritto di utilizzare il contenuto, forze dell'ordine o periti incaricati
- Rispetta i termini di servizio dei siti web
- Non utilizzare per attività illegali o non autorizzate
- Considera le leggi locali sulla privacy e protezione dati

### 🤝 Uso Etico
- Non sovraccaricare i server target
- Rispetta il file robots.txt
- Usa responsabilmente per scopi di sicurezza e ricerca
- Non divulgare informazioni sensibili trovate

### 📋 Disclaimer
Questo strumento è fornito solo per scopi educativi e di ricerca sulla sicurezza. L'utente è responsabile dell'uso appropriato e legale del software.

## 🔍 Esempi di Analisi

### Esempio Output JSON
```json
{
  "target": "https://example.com",
  "domain": "example.com",
  "timestamp": "2023-12-01T14:30:22",
  "analysis": {
    "basic_info": {
      "status_code": 200,
      "title": "Example Domain",
      "server": "nginx/1.18.0"
    },
    "geolocation": {
      "ip_address": "93.184.216.34",
      "country": "United States",
      "city": "Norwell"
    },
    "technologies": {
      "web-servers": ["Nginx"],
      "programming-languages": ["PHP"]
    }
  }
}
```

### Esempio Sottodomini Trovati
```
✓ Trovati 5 sottodomini:
- www.example.com
- mail.example.com
- ftp.example.com
- admin.example.com
- api.example.com
```

## 🚨 Troubleshooting

### Problemi Comuni

1. **Errore Chrome Driver**
   ```
   Soluzione: Installa Google Chrome o aggiorna ChromeDriver
   ```

2. **Timeout delle Richieste**
   ```
   Soluzione: Aumenta il timeout o controlla la connessione
   ```

3. **Dipendenze Mancanti**
   ```
   Soluzione: Esegui pip3 install -r requirements.txt
   ```

4. **Permessi Directory**
   ```
   Soluzione: Verifica i permessi di scrittura nella directory
   ```

### Debug Mode
Per attivare il debug, modifica il livello di logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 🔄 Aggiornamenti e Sviluppo

### Roadmap
- [x] Analisi malware e phishing (URLVoid, analisi pattern)
- [X] Export in formato html
- [ ] Interfaccia web
- [x] Integrazione Wayback Machine (cronologia siti web)
- [ ] Analisi social media avanzata


## Supporto

Per supporto, bug report, richieste di feature o licenze commerciali:
- Apri una **GitHub Issue**
- Fornisci log dettagliati
- Specifica sistema operativo e versione Python
- Per licenze commerciali, usa il tag `[COMMERCIAL]` nel titolo

## 📄 Licenza

Questo progetto è rilasciato sotto **GNU Affero General Public License v3**.

[![AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

### Termini della Licenza:
- ✅ **Uso libero** per scopi non commerciali, educativi e forensi
- ✅ **Codice sorgente** deve rimanere aperto per qualsiasi modifica
- ❌ **Uso commerciale vietato** senza licenza separata
- ❌ **Modifiche nascoste vietate** (devono essere pubbliche)

### Clausola Forense Speciale:
Per preservare l'integrità forense, qualsiasi modifica deve:
1. Essere documentata pubblicamente
2. Mantenere la tracciabilità delle modifiche
3. Non compromettere la veridicità dei risultati

### Uso Commerciale
Per uso commerciale, apri una **GitHub Issue** per discutere le opzioni di licenza.

---

**⚠️ Ricorda: Usa questo strumento responsabilmente e in modo etico, il creatore del tool non ha nessuna responsabilità sull'uso che l'utente principale effettua, informati sulle leggi di privacy disposte nel tuo paese e nel rispetto delle leggi applicabili.
E' severamente vietata la replica abusiva per usi commerciali e la modifica del codice sorgente, qualunque sia il motivo, la modifica potrebbe compromettere la funzionalità e la veridicità dei dati ottenuti in analisi, pertanto non è permessa la pubblicazione o la distribuzione del codice modificato senza un permesso da parte dello sviluppatore.
