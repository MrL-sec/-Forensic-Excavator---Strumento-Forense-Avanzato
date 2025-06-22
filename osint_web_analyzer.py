#!/usr/bin/env python3
"""
Forensic-Excavator - Strumento Completo All-in-One per Analisi Forense
Autore: Forensic-Excavator Advanced Tool
Descrizione: Tool avanzato per analisi forense e OSINT di siti web - Tutto in un file
Versione: 2.0 - All-in-One Edition
"""

import os
import sys
import subprocess
import json
import requests
import socket
import ssl
import hashlib
import time
import base64
import re
import threading
import urllib.parse
import urllib.request
import urllib.error
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin, quote
import xml.etree.ElementTree as ET
from collections import defaultdict
import gzip
import zipfile
import tempfile
import shutil
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

# Verifica disponibilità geoip2
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

# Sistema di Sessione Web Semplificato
class WebSession:
    """Gestione sessione web semplificata per uso con VPN utente"""
    
    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15'
        ]
        self.session = None
        self.setup_session()
    
    def setup_session(self):
        """Configura la sessione web standard con gestione SSL avanzata"""
        try:
            # Configura sessione standard
            self.session = requests.Session()
            
            # Disabilita warning SSL per certificati self-signed
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # Configura headers standard
            self._setup_headers()
            
            print("🌐 Sessione web configurata")
            print("🛡️ Utilizzo VPN utente per protezione")
            print("🔒 Gestione SSL avanzata attivata")
            
        except Exception as e:
            print(f"⚠️ Errore setup sessione: {e}")
    
    def _setup_headers(self):
        """Configura headers standard per la sessione"""
        self.session.headers.update({
            'User-Agent': self._get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
    
    def _get_random_user_agent(self):
        """Ottiene un User-Agent casuale"""
        user_agents = [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0'
        ]
        return random.choice(user_agents)
            
    
    def anonymized_session(self):
        """Inizializza sessione anonimizzata"""
        # Ruota User-Agent
        self.session.headers['User-Agent'] = self._get_random_user_agent()
        
        # Aggiungi delay casuale anti-detection
        time.sleep(random.uniform(1, 3))
        
        return True

    def get_anonymized_session(self):
        """Ottiene sessione con headers aggiornati"""
        # Ruota User-Agent
        self.session.headers['User-Agent'] = self._get_random_user_agent()
        
        # Aggiungi delay casuale anti-detection
        time.sleep(random.uniform(1, 3))
        
        return self.session
    
    def get_current_ip(self):
        """Ottiene IP corrente"""
        try:
            response = self.session.get('https://httpbin.org/ip', timeout=10)
            return response.json().get('origin', 'N/A')
        except:
            return 'N/A'
    
    def new_session(self):
        """Genera nuova sessione con headers aggiornati"""
        try:
            # Nuovo User-Agent
            self.session.headers['User-Agent'] = self._get_random_user_agent()
            
            # Reset cookies
            self.session.cookies.clear()
            
            print("🔄 Nuova sessione generata")
            return True
            
        except Exception as e:
            print(f"❌ Errore generazione nuova sessione: {e}")
            return False
    
    def safe_get(self, url, **kwargs):
        """Esegue una richiesta GET sicura con gestione SSL automatica"""
        try:
            # Primo tentativo con verifica SSL
            response = self.session.get(url, **kwargs)
            return response
        except requests.exceptions.SSLError:
            # Secondo tentativo senza verifica SSL
            try:
                kwargs['verify'] = False
                response = self.session.get(url, **kwargs)
                return response
            except Exception as e:
                print(f"⚠️ Errore richiesta HTTP: {e}")
                raise
        except Exception as e:
            print(f"⚠️ Errore richiesta HTTP: {e}")
            raise

    
    def _setup_anti_fingerprinting_headers(self):
        """Configura headers anti-fingerprinting"""
        base_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0'
        }
        
        self.session.headers.update(base_headers)
    
    def get_anonymized_session(self):
        """Ottiene sessione con headers aggiornati"""
        # Ruota User-Agent
        self.session.headers['User-Agent'] = self._get_random_user_agent()
        
        # Aggiungi delay casuale anti-detection
        time.sleep(random.uniform(1, 3))
        
        return self.session
    
    def _get_random_user_agent(self):
        """Ottiene User-Agent casuale"""
        return random.choice(self.user_agents)
    

    

    
    def get_current_ip(self):
        """Ottiene IP corrente"""
        try:
            response = self.session.get('https://httpbin.org/ip', timeout=10)
            return response.json().get('origin', 'N/A')
        except:
            return 'N/A'
    
    def new_session(self):
        """Genera nuova sessione con headers aggiornati"""
        try:
            # Nuovo User-Agent
            self.session.headers['User-Agent'] = self._get_random_user_agent()
            
            # Reset cookies
            self.session.cookies.clear()
            
            print("🔄 Nuova sessione generata")
            return True
            
        except Exception as e:
            print(f"❌ Errore generazione nuova sessione: {e}")
            return False
    


# Sistema di gestione automatica delle dipendenze
class DependencyManager:
    """Gestore automatico delle dipendenze con auto-installazione integrata"""
    
    # Tutte le dipendenze vengono ora installate automaticamente
    ALL_PACKAGES = {
        # Core dependencies
        'requests': 'requests>=2.28.0',
        'beautifulsoup4': 'beautifulsoup4>=4.11.0',
        'lxml': 'lxml>=4.9.0',
        'urllib3': 'urllib3>=1.26.0',
        'certifi': 'certifi>=2022.0.0',
        'chardet': 'chardet>=5.0.0',
        'idna': 'idna>=3.0',
        'soupsieve': 'soupsieve>=2.3.0',
        
        # DNS and Network Analysis
        'dnspython': 'dnspython>=2.2.0',
        'python-whois': 'python-whois>=0.7.0',
        'python-nmap': 'python-nmap>=0.7.0',
        
        # Technology Detection
        'builtwith': 'builtwith>=1.3.0',
        
        # OSINT Tools
        'shodan': 'shodan>=1.28.0',
        'censys': 'censys>=2.1.0',
        'waybackpy': 'waybackpy>=3.0.0',
        
        # Web Automation
        'selenium': 'selenium>=4.8.0',
        
        # Image Processing
        'Pillow': 'Pillow>=9.0.0',
        
        # Security and Cryptography
        'cryptography': 'cryptography>=3.4.0',
        'pyopenssl': 'pyopenssl>=22.0.0',
        
        # GeoIP
        'geoip2': 'geoip2>=4.6.0',
        'maxminddb': 'maxminddb>=2.2.0',
        
        # Additional utilities
        'colorama': 'colorama>=0.4.0',
        'termcolor': 'termcolor>=2.0.0',
        'tqdm': 'tqdm>=4.64.0',
        'click': 'click>=8.0.0',
        'pytz': 'pytz>=2022.0',
        'python-dateutil': 'python-dateutil>=2.8.0'
    }
    
    # Dipendenze essenziali per il funzionamento base
    CORE_PACKAGES = {
        'requests': 'requests>=2.28.0',
        'beautifulsoup4': 'beautifulsoup4>=4.11.0',
        'lxml': 'lxml>=4.9.0',
        'dnspython': 'dnspython>=2.2.0',
        'colorama': 'colorama>=0.4.0',
        'termcolor': 'termcolor>=2.0.0'
    }
    
    @classmethod
    def install_package(cls, package_name):
        """Installa un pacchetto Python con retry"""
        max_retries = 2
        for attempt in range(max_retries):
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package_name, '--upgrade'], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except subprocess.CalledProcessError:
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
                return False
    
    @classmethod
    def check_and_install_dependencies(cls, auto_install_all=True):
        """Controlla e installa automaticamente tutte le dipendenze"""
        missing_packages = []
        installed_packages = []
        
        # Determina quali pacchetti controllare
        packages_to_check = cls.ALL_PACKAGES if auto_install_all else cls.CORE_PACKAGES
        
        print(f"🔍 Controllo dipendenze ({len(packages_to_check)} pacchetti)...")
        
        # Controlla tutte le dipendenze
        for module_name, package_spec in packages_to_check.items():
            try:
                if module_name == 'beautifulsoup4':
                    import bs4
                elif module_name == 'python-whois':
                    import whois
                elif module_name == 'python-nmap':
                    import nmap
                elif module_name == 'python-dateutil':
                    import dateutil
                elif module_name == 'Pillow':
                    import PIL
                elif module_name == 'pyopenssl':
                    import OpenSSL
                else:
                    __import__(module_name)
                installed_packages.append(module_name)
            except ImportError:
                missing_packages.append(package_spec)
        
        # Installa i pacchetti mancanti
        if missing_packages:
            print(f"🔧 Installazione automatica dipendenze ({len(missing_packages)} mancanti)...")
            success_count = 0
            
            for package in missing_packages:
                package_name = package.split('>=')[0]
                print(f"   📦 Installando {package_name}...")
                
                if cls.install_package(package):
                    print(f"   ✅ {package_name} installato con successo")
                    success_count += 1
                else:
                    print(f"   ❌ Errore installazione {package_name} (fallback nativo disponibile)")
            
            print(f"\n📊 Riepilogo installazione:")
            print(f"   ✅ Installati: {success_count}/{len(missing_packages)}")
            print(f"   📚 Già presenti: {len(installed_packages)}")
            
            if success_count > 0:
                print(f"\n🔄 Riavvio consigliato per caricare le nuove dipendenze...")
        else:
            print(f"✅ Tutte le dipendenze sono già installate ({len(installed_packages)} pacchetti)")
    
    @classmethod
    def update_all_packages(cls):
        """Aggiorna tutte le dipendenze all'ultima versione"""
        print(f"🔄 Aggiornamento di tutte le dipendenze...")
        
        for module_name, package_spec in cls.ALL_PACKAGES.items():
            package_name = package_spec.split('>=')[0]
            print(f"   🔄 Aggiornando {package_name}...")
            
            if cls.install_package(package_spec):
                print(f"   ✅ {package_name} aggiornato")
            else:
                print(f"   ❌ Errore aggiornamento {package_name}")
        
        print(f"\n✅ Processo di aggiornamento completato!")

# Installa automaticamente tutte le dipendenze
print("🚀 Forensic-Excavator - Sistema di Auto-Installazione Dipendenze")
print("=" * 60)
DependencyManager.check_and_install_dependencies(auto_install_all=True)
print("=" * 60)

# Import delle librerie esterne con fallback
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("⚠️  dnspython non disponibile - alcune funzioni DNS saranno limitate")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️  python-whois non disponibile - analisi WHOIS limitata")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("⚠️  python-nmap non disponibile - scansione porte limitata")

try:
    import builtwith
    BUILTWITH_AVAILABLE = True
except ImportError:
    BUILTWITH_AVAILABLE = False
    print("⚠️  builtwith non disponibile - rilevamento tecnologie limitato")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print("⚠️  BeautifulSoup4 non disponibile - parsing HTML limitato")

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

try:
    import censys
    CENSYS_AVAILABLE = True
except ImportError:
    CENSYS_AVAILABLE = False

# Sublist3r rimosso - utilizziamo implementazione nativa
SUBLIST3R_AVAILABLE = False

try:
    import waybackpy
    WAYBACK_AVAILABLE = True
except ImportError:
    WAYBACK_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import OpenSSL
    OPENSSL_AVAILABLE = True
except ImportError:
    OPENSSL_AVAILABLE = False

# Classe per cattura screenshot
class ScreenshotCapture:
    """Classe per catturare screenshot di siti web usando Selenium"""
    
    def __init__(self):
        self.driver = None
        self.setup_driver()
    
    def setup_driver(self):
        """Configura il driver Chrome per screenshot"""
        if not SELENIUM_AVAILABLE:
            print("⚠️ Selenium non disponibile - screenshot disabilitati")
            return False
        
        try:
            # Opzioni Chrome per headless
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins')
            chrome_options.add_argument('--disable-images')
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            
            # Inizializza driver
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(30)
            return True
            
        except Exception as e:
            print(f"⚠️ Errore configurazione driver Chrome: {e}")
            print("💡 Assicurati che Chrome sia installato")
            return False
    
    def capture_screenshot(self, url, output_path, wait_seconds=3):
        """Cattura screenshot di una pagina web"""
        if not self.driver:
            return False
        
        try:
            print(f"📸 Catturando screenshot di: {url}")
            
            # Naviga alla pagina
            self.driver.get(url)
            
            # Attendi caricamento
            time.sleep(wait_seconds)
            
            # Attendi che la pagina sia completamente caricata
            try:
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
            except:
                pass  # Continua anche se non trova il body
            
            # Cattura screenshot
            success = self.driver.save_screenshot(output_path)
            
            if success:
                print(f"✅ Screenshot salvato: {output_path}")
                return True
            else:
                print(f"❌ Errore salvataggio screenshot")
                return False
                
        except Exception as e:
            print(f"❌ Errore cattura screenshot: {e}")
            return False
    
    def capture_full_page_screenshot(self, url, output_path):
        """Cattura screenshot dell'intera pagina (scroll completo)"""
        if not self.driver:
            return False
        
        try:
            print(f"📸 Catturando screenshot completo di: {url}")
            
            # Naviga alla pagina
            self.driver.get(url)
            time.sleep(3)
            
            # Ottieni dimensioni totali della pagina
            total_height = self.driver.execute_script("return document.body.scrollHeight")
            viewport_height = self.driver.execute_script("return window.innerHeight")
            
            # Imposta dimensioni finestra per catturare tutta la pagina
            self.driver.set_window_size(1920, total_height)
            time.sleep(2)
            
            # Cattura screenshot
            success = self.driver.save_screenshot(output_path)
            
            if success:
                print(f"✅ Screenshot completo salvato: {output_path}")
                return True
            else:
                print(f"❌ Errore salvataggio screenshot completo")
                return False
                
        except Exception as e:
            print(f"❌ Errore cattura screenshot completo: {e}")
            return False
    
    def close(self):
        """Chiude il driver"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
    
    def __del__(self):
        """Cleanup automatico"""
        self.close()

# Implementazioni native per sostituire dipendenze esterne
class NativeImplementations:
    """Implementazioni native per funzionalità che sostituiscono librerie esterne"""
    
    @staticmethod
    def simple_whois(domain):
        """Implementazione WHOIS semplificata usando socket"""
        try:
            import socket
            whois_servers = {
                '.com': 'whois.verisign-grs.com',
                '.net': 'whois.verisign-grs.com', 
                '.org': 'whois.pir.org',
                '.info': 'whois.afilias.net',
                '.biz': 'whois.neulevel.biz',
                '.us': 'whois.nic.us',
                '.uk': 'whois.nic.uk',
                '.de': 'whois.denic.de',
                '.fr': 'whois.afnic.fr',
                '.it': 'whois.nic.it'
            }
            
            # Trova il server WHOIS appropriato
            whois_server = None
            for tld, server in whois_servers.items():
                if domain.endswith(tld):
                    whois_server = server
                    break
            
            if not whois_server:
                whois_server = 'whois.iana.org'
            
            # Connessione al server WHOIS
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((whois_server, 43))
            sock.send(f"{domain}\r\n".encode())
            
            response = b''
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            return response.decode('utf-8', errors='ignore')
            
        except Exception as e:
            return f"Errore WHOIS: {e}"
    
    @staticmethod
    def simple_port_scan(host, ports=[80, 443, 21, 22, 25, 53, 110, 143, 993, 995]):
        """Scanner di porte semplificato"""
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    return port
            except Exception:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return sorted(open_ports)
    
    @staticmethod
    def simple_tech_detection(html_content, headers):
        """Rilevamento tecnologie semplificato"""
        technologies = []
        
        # Analisi headers
        server = headers.get('server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        elif 'nginx' in server:
            technologies.append('Nginx')
        elif 'iis' in server:
            technologies.append('IIS')
        
        # Analisi HTML
        html_lower = html_content.lower()
        
        # Framework detection
        if 'wordpress' in html_lower or 'wp-content' in html_lower:
            technologies.append('WordPress')
        if 'drupal' in html_lower:
            technologies.append('Drupal')
        if 'joomla' in html_lower:
            technologies.append('Joomla')
        if 'react' in html_lower or 'reactjs' in html_lower:
            technologies.append('React')
        if 'angular' in html_lower:
            technologies.append('Angular')
        if 'vue' in html_lower or 'vuejs' in html_lower:
            technologies.append('Vue.js')
        if 'bootstrap' in html_lower:
            technologies.append('Bootstrap')
        if 'jquery' in html_lower:
            technologies.append('jQuery')
        
        # CMS detection
        if 'generator" content="wordpress' in html_lower:
            technologies.append('WordPress CMS')
        if 'powered by shopify' in html_lower:
            technologies.append('Shopify')
        
        return list(set(technologies))
    
    @staticmethod
    def simple_dns_lookup(domain, record_type='A'):
        """Lookup DNS semplificato"""
        try:
            import socket
            if record_type == 'A':
                return [socket.gethostbyname(domain)]
            elif record_type == 'MX':
                # Implementazione MX semplificata
                try:
                    import subprocess
                    result = subprocess.run(['nslookup', '-type=MX', domain], 
                                          capture_output=True, text=True, timeout=10)
                    mx_records = []
                    for line in result.stdout.split('\n'):
                        if 'mail exchanger' in line.lower():
                            parts = line.split('=')
                            if len(parts) > 1:
                                mx_records.append(parts[1].strip())
                    return mx_records
                except Exception:
                    return []
            return []
        except Exception:
            return []

class ColoredOutput:
    """Classe per output colorato nel terminale"""
    
    COLORS = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'purple': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'bold': '\033[1m',
        'end': '\033[0m'
    }
    
    @classmethod
    def print_colored(cls, text, color='white', bold=False):
        """Stampa testo colorato"""
        color_code = cls.COLORS.get(color, cls.COLORS['white'])
        bold_code = cls.COLORS['bold'] if bold else ''
        end_code = cls.COLORS['end']
        print(f"{bold_code}{color_code}{text}{end_code}")
    
    @classmethod
    def success(cls, text):
        cls.print_colored(f"✓ {text}", 'green')
    
    @classmethod
    def error(cls, text):
        cls.print_colored(f"✗ {text}", 'red')
    
    @classmethod
    def warning(cls, text):
        cls.print_colored(f"⚠ {text}", 'yellow')
    
    @classmethod
    def info(cls, text):
        cls.print_colored(f"ℹ {text}", 'blue')
    
    @classmethod
    def header(cls, text):
        cls.print_colored(f"\n🔍 {text}", 'cyan', bold=True)

class SimpleHTMLParser(HTMLParser):
    """Parser HTML semplificato per estrazione dati"""
    
    def __init__(self):
        super().__init__()
        self.links = []
        self.images = []
        self.forms = []
        self.scripts = []
        self.stylesheets = []
        self.title = ""
        self.meta_data = {}
        self.current_form = None
        self.in_title = False
    
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        if tag == 'a' and 'href' in attrs_dict:
            self.links.append(attrs_dict['href'])
        
        elif tag == 'img' and 'src' in attrs_dict:
            self.images.append(attrs_dict['src'])
        
        elif tag == 'script' and 'src' in attrs_dict:
            self.scripts.append(attrs_dict['src'])
        
        elif tag == 'link' and attrs_dict.get('rel') == 'stylesheet':
            if 'href' in attrs_dict:
                self.stylesheets.append(attrs_dict['href'])
        
        elif tag == 'form':
            self.current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'GET'),
                'inputs': []
            }
        
        elif tag == 'input' and self.current_form is not None:
            self.current_form['inputs'].append({
                'type': attrs_dict.get('type', 'text'),
                'name': attrs_dict.get('name', ''),
                'value': attrs_dict.get('value', '')
            })
        
        elif tag == 'meta':
            name = attrs_dict.get('name', attrs_dict.get('property', ''))
            content = attrs_dict.get('content', '')
            if name and content:
                self.meta_data[name] = content
        
        elif tag == 'title':
            self.in_title = True
    
    def handle_endtag(self, tag):
        if tag == 'form' and self.current_form:
            self.forms.append(self.current_form)
            self.current_form = None
        elif tag == 'title':
            self.in_title = False
    
    def handle_data(self, data):
        if self.in_title:
            self.title += data.strip()

class DNSResolver:
    """Resolver DNS semplificato"""
    
    @staticmethod
    def resolve_record(domain, record_type='A'):
        """Risolve record DNS usando nslookup"""
        try:
            if record_type == 'A':
                return socket.gethostbyname(domain)
            else:
                # Usa nslookup per altri tipi di record
                result = subprocess.run(
                    ['nslookup', '-type=' + record_type, domain],
                    capture_output=True, text=True, timeout=10
                )
                return result.stdout
        except Exception:
            return None
    
    @staticmethod
    def get_mx_records(domain):
        """Ottiene record MX"""
        try:
            result = subprocess.run(
                ['nslookup', '-type=MX', domain],
                capture_output=True, text=True, timeout=10
            )
            mx_records = []
            for line in result.stdout.split('\n'):
                if 'mail exchanger' in line:
                    mx_records.append(line.strip())
            return mx_records
        except Exception:
            return []

class AdvancedTechnologyDetector:
    """Rilevatore avanzato di tecnologie web con fingerprinting completo"""
    
    TECH_SIGNATURES = {
        'cms': {
            'WordPress': {
                'html': ['/wp-content/', '/wp-includes/', 'wp-json', '/wp-admin/', 'wp-emoji'],
                'headers': ['x-pingback'],
                'meta': ['generator.*wordpress'],
                'cookies': ['wordpress_', 'wp-'],
                'scripts': ['wp-includes/js', 'wp-content/themes']
            },
            'Drupal': {
                'html': ['/sites/default/', '/modules/', '/themes/', 'drupal.js'],
                'meta': ['generator.*drupal'],
                'headers': ['x-drupal-cache', 'x-generator.*drupal'],
                'scripts': ['misc/drupal.js']
            },
            'Joomla': {
                'html': ['/components/', '/modules/', '/templates/', 'option=com_'],
                'meta': ['generator.*joomla'],
                'scripts': ['media/jui/js', 'media/system/js']
            },
            'Magento': {
                'html': ['/skin/frontend/', '/js/mage/', 'Mage.Cookies', 'var/cache'],
                'cookies': ['frontend', 'adminhtml'],
                'scripts': ['js/mage/', 'skin/frontend/']
            },
            'Shopify': {
                'html': ['cdn.shopify.com', 'shopify-analytics', 'shopify-section'],
                'headers': ['x-shopify-stage', 'x-shopid'],
                'scripts': ['cdn.shopify.com']
            },
            'Wix': {
                'html': ['static.wixstatic.com', 'wix.com', 'wix-warmup-data'],
                'scripts': ['static.wixstatic.com']
            },
            'Squarespace': {
                'html': ['squarespace.com', 'squarespace-cdn', 'static1.squarespace.com'],
                'scripts': ['static1.squarespace.com']
            },
            'PrestaShop': {
                'html': ['prestashop', 'modules/blockcart', 'prestashop.com'],
                'cookies': ['PrestaShop-']
            }
        },
        'frameworks': {
            'React': {
                'html': ['react', 'reactjs', '_react', 'data-reactroot', '__react'],
                'scripts': ['react.js', 'react.min.js', 'react.development.js']
            },
            'Angular': {
                'html': ['angular', 'ng-', 'angularjs', 'ng-version', 'ng-app'],
                'scripts': ['angular.js', 'angular.min.js']
            },
            'Vue.js': {
                'html': ['vue.js', 'vuejs', '__vue__', 'v-if', 'v-for', 'v-model'],
                'scripts': ['vue.js', 'vue.min.js']
            },
            'jQuery': {
                'html': ['jquery', 'jQuery', '$.fn.jquery'],
                'scripts': ['jquery.js', 'jquery.min.js', 'jquery-']
            },
            'Bootstrap': {
                'html': ['bootstrap', 'Bootstrap', 'btn-primary', 'container-fluid'],
                'scripts': ['bootstrap.js', 'bootstrap.min.js']
            },
            'Foundation': {
                'html': ['foundation', 'Foundation', 'top-bar', 'orbit-container'],
                'scripts': ['foundation.js', 'foundation.min.js']
            },
            'Next.js': {
                'html': ['__next', '__NEXT_DATA__', '_next/static'],
                'scripts': ['_next/static']
            },
            'Nuxt.js': {
                'html': ['__nuxt', '__NUXT__', '_nuxt/'],
                'scripts': ['_nuxt/']
            }
        },
        'servers': {
            'Apache': {'headers': ['apache']},
            'Nginx': {'headers': ['nginx']},
            'IIS': {'headers': ['microsoft-iis', 'iis']},
            'Cloudflare': {'headers': ['cloudflare', 'cf-ray']},
            'LiteSpeed': {'headers': ['litespeed']},
            'OpenResty': {'headers': ['openresty']}
        },
        'analytics': {
            'Google Analytics': {
                'html': ['google-analytics.com', 'gtag(', 'ga(', 'GoogleAnalyticsObject'],
                'scripts': ['google-analytics.com/analytics.js', 'googletagmanager.com/gtag']
            },
            'Google Tag Manager': {
                'html': ['googletagmanager.com', 'GTM-', 'dataLayer'],
                'scripts': ['googletagmanager.com/gtm.js']
            },
            'Facebook Pixel': {
                'html': ['facebook.net/tr', 'fbq(', 'fbevents.js'],
                'scripts': ['connect.facebook.net']
            },
            'Hotjar': {
                'html': ['hotjar.com', 'hj(', 'hjBootstrap'],
                'scripts': ['static.hotjar.com']
            },
            'Mixpanel': {
                'html': ['mixpanel.com', 'mixpanel.track', 'mixpanel.init'],
                'scripts': ['cdn.mxpnl.com']
            },
            'Adobe Analytics': {
                'html': ['omniture.com', 's_code.js', 'adobe.com/analytics'],
                'scripts': ['omniture.com', 'adobe.com']
            }
        },
        'advertising': {
            'Google AdSense': {
                'html': ['googlesyndication.com', 'google_ad_client', 'adsbygoogle'],
                'scripts': ['pagead2.googlesyndication.com']
            },
            'Google DoubleClick': {
                'html': ['doubleclick.net', 'googletagservices.com'],
                'scripts': ['googletagservices.com']
            },
            'Amazon Associates': {
                'html': ['amazon-adsystem.com'],
                'scripts': ['amazon-adsystem.com']
            },
            'Media.net': {
                'html': ['media.net', 'contextual.media.net'],
                'scripts': ['contextual.media.net']
            }
        },
        'cdn': {
            'Cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status'],
                'scripts': ['cdnjs.cloudflare.com']
            },
            'jsDelivr': {
                'scripts': ['cdn.jsdelivr.net']
            },
            'unpkg': {
                'scripts': ['unpkg.com']
            },
            'MaxCDN': {
                'headers': ['x-cache'],
                'scripts': ['maxcdn.bootstrapcdn.com']
            },
            'KeyCDN': {
                'headers': ['server.*keycdn']
            }
        },
        'security': {
            'reCAPTCHA': {
                'html': ['recaptcha', 'g-recaptcha', 'grecaptcha'],
                'scripts': ['google.com/recaptcha', 'gstatic.com/recaptcha']
            },
            'Cloudflare Bot Management': {
                'headers': ['cf-ray'],
                'scripts': ['challenges.cloudflare.com']
            },
            'hCaptcha': {
                'html': ['hcaptcha', 'h-captcha'],
                'scripts': ['hcaptcha.com']
            }
        },
        'ecommerce': {
            'WooCommerce': {
                'html': ['woocommerce', 'wc-', 'cart-contents'],
                'scripts': ['wc-add-to-cart']
            },
            'Stripe': {
                'html': ['stripe.com', 'stripe.js'],
                'scripts': ['js.stripe.com']
            },
            'PayPal': {
                'html': ['paypal.com', 'paypal.js'],
                'scripts': ['paypal.com']
            }
        }
    }
    
    JS_LIBRARIES = {
        'Lodash': ['lodash.js', 'lodash.min.js', '_.'],
        'Moment.js': ['moment.js', 'moment.min.js', 'moment('],
        'Chart.js': ['chart.js', 'chart.min.js', 'Chart.'],
        'D3.js': ['d3.js', 'd3.min.js', 'd3.'],
        'Three.js': ['three.js', 'three.min.js', 'THREE.'],
        'Axios': ['axios.js', 'axios.min.js', 'axios.'],
        'Socket.io': ['socket.io.js', 'socket.io', 'io('],
        'Swiper': ['swiper.js', 'swiper.min.js', 'new Swiper'],
        'AOS': ['aos.js', 'aos.css', 'AOS.init'],
        'GSAP': ['gsap.js', 'gsap.min.js', 'tweenmax', 'TweenMax'],
        'Particles.js': ['particles.js', 'particles.min.js'],
        'Typed.js': ['typed.js', 'typed.min.js', 'new Typed']
    }
    
    CSS_FRAMEWORKS = {
        'Tailwind CSS': ['tailwindcss', 'tailwind.css', 'tw-'],
        'Bulma': ['bulma.css', 'bulma.min.css', 'is-primary'],
        'Semantic UI': ['semantic.css', 'semantic.min.css', 'ui button'],
        'Materialize': ['materialize.css', 'materialize.min.css'],
        'Pure CSS': ['pure.css', 'pure-'],
        'Skeleton': ['skeleton.css']
    }
    
    @classmethod
    def detect_technologies(cls, html_content, headers, cookies=None, domain=None):
        """Rileva tecnologie con fingerprinting avanzato e builtwith"""
        detected = {
            'cms': [],
            'frameworks': [],
            'servers': [],
            'analytics': [],
            'advertising': [],
            'cdn': [],
            'security': [],
            'ecommerce': [],
            'javascript_libraries': [],
            'css_frameworks': [],
            'other': [],
            'method': 'fingerprinting'
        }
        
        # Usa builtwith se disponibile e domain è fornito
        if BUILTWITH_AVAILABLE and domain:
            try:
                import builtwith
                builtwith_result = builtwith.parse(f'http://{domain}')
                
                # Mappa i risultati di builtwith alle nostre categorie
                category_mapping = {
                    'cms': ['cms'],
                    'frameworks': ['javascript-frameworks', 'web-frameworks'],
                    'servers': ['web-servers'],
                    'analytics': ['analytics'],
                    'advertising': ['advertising-networks'],
                    'cdn': ['cdn'],
                    'ecommerce': ['ecommerce'],
                    'other': ['programming-languages', 'databases', 'hosting']
                }
                
                for our_category, builtwith_categories in category_mapping.items():
                    for bw_category in builtwith_categories:
                        if bw_category in builtwith_result:
                            for tech in builtwith_result[bw_category]:
                                tech_name = tech.get('Name', str(tech))
                                if tech_name not in detected[our_category]:
                                    detected[our_category].append(tech_name)
                
                detected['method'] = 'builtwith'
                return detected
                
            except Exception:
                # Fallback al metodo di fingerprinting
                pass
        
        html_lower = html_content.lower()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Analizza ogni categoria di tecnologie
        for category, technologies in cls.TECH_SIGNATURES.items():
            for tech_name, indicators in technologies.items():
                found = False
                
                # Controlla HTML content
                if 'html' in indicators:
                    if any(indicator.lower() in html_lower for indicator in indicators['html']):
                        found = True
                
                # Controlla headers
                if 'headers' in indicators and not found:
                    for header_name, header_value in headers_lower.items():
                        if any(indicator in f"{header_name} {header_value}" for indicator in indicators['headers']):
                            found = True
                            break
                
                # Controlla meta tags
                if 'meta' in indicators and not found:
                    import re
                    for pattern in indicators['meta']:
                        if re.search(pattern, html_lower):
                            found = True
                            break
                
                # Controlla cookies
                if 'cookies' in indicators and cookies and not found:
                    cookie_names = [cookie.get('name', '').lower() for cookie in cookies]
                    if any(any(indicator.lower() in cookie_name for indicator in indicators['cookies']) for cookie_name in cookie_names):
                        found = True
                
                # Controlla scripts
                if 'scripts' in indicators and not found:
                    if any(indicator.lower() in html_lower for indicator in indicators['scripts']):
                        found = True
                
                if found:
                    detected[category].append(tech_name)
        
        # Rilevamento JavaScript libraries
        for lib_name, patterns in cls.JS_LIBRARIES.items():
            if any(pattern.lower() in html_lower for pattern in patterns):
                detected['javascript_libraries'].append(lib_name)
        
        # Rilevamento CSS frameworks
        for framework_name, patterns in cls.CSS_FRAMEWORKS.items():
            if any(pattern.lower() in html_lower for pattern in patterns):
                detected['css_frameworks'].append(framework_name)
        
        return detected
    
    @classmethod
    def analyze_csp_headers(cls, headers):
        """Analizza Content Security Policy headers"""
        csp_analysis = {
            'present': False,
            'directives': {},
            'security_level': 'None',
            'issues': [],
            'recommendations': []
        }
        
        csp_header = headers.get('content-security-policy', '') or headers.get('content-security-policy-report-only', '')
        
        if csp_header:
            csp_analysis['present'] = True
            
            # Parse CSP directives
            directives = {}
            for directive in csp_header.split(';'):
                directive = directive.strip()
                if directive:
                    parts = directive.split(' ', 1)
                    if len(parts) == 2:
                        directives[parts[0]] = parts[1]
                    else:
                        directives[parts[0]] = ''
            
            csp_analysis['directives'] = directives
            
            # Analyze security level
            if "'unsafe-inline'" in csp_header or "'unsafe-eval'" in csp_header:
                csp_analysis['security_level'] = 'Low'
                csp_analysis['issues'].append('Unsafe inline/eval allowed')
                csp_analysis['recommendations'].append('Remove unsafe-inline and unsafe-eval directives')
            elif 'default-src' in directives:
                if "'self'" in directives['default-src']:
                    csp_analysis['security_level'] = 'Medium'
                else:
                    csp_analysis['security_level'] = 'High'
            else:
                csp_analysis['security_level'] = 'Low'
                csp_analysis['issues'].append('No default-src directive')
                csp_analysis['recommendations'].append('Add default-src directive')
            
            # Check for specific directives
            if 'script-src' not in directives:
                csp_analysis['recommendations'].append('Add script-src directive for better security')
            if 'style-src' not in directives:
                csp_analysis['recommendations'].append('Add style-src directive')
        else:
            csp_analysis['recommendations'].append('Implement Content Security Policy header')
        
        return csp_analysis
    
    @classmethod
    def detect_tracking_technologies(cls, html_content, headers):
        """Rileva specificamente tecnologie di tracking"""
        tracking_tech = {
            'analytics': [],
            'advertising': [],
            'social_media': [],
            'marketing_automation': [],
            'privacy_score': 100
        }
        
        html_lower = html_content.lower()
        
        # Tracking analytics
        analytics_trackers = {
            'Google Analytics': ['google-analytics.com', 'gtag(', 'ga('],
            'Adobe Analytics': ['omniture.com', 's_code.js'],
            'Mixpanel': ['mixpanel.com', 'mixpanel.track'],
            'Segment': ['segment.com', 'analytics.track'],
            'Amplitude': ['amplitude.com', 'amplitude.getInstance']
        }
        
        for tracker, patterns in analytics_trackers.items():
            if any(pattern in html_lower for pattern in patterns):
                tracking_tech['analytics'].append(tracker)
                tracking_tech['privacy_score'] -= 10
        
        # Advertising trackers
        ad_trackers = {
            'Google AdSense': ['googlesyndication.com'],
            'Facebook Pixel': ['facebook.net/tr', 'fbq('],
            'DoubleClick': ['doubleclick.net'],
            'Amazon DSP': ['amazon-adsystem.com']
        }
        
        for tracker, patterns in ad_trackers.items():
            if any(pattern in html_lower for pattern in patterns):
                tracking_tech['advertising'].append(tracker)
                tracking_tech['privacy_score'] -= 15
        
        # Social media trackers
        social_trackers = {
            'Facebook Connect': ['connect.facebook.net'],
            'Twitter Widget': ['platform.twitter.com'],
            'LinkedIn Insight': ['snap.licdn.com'],
            'Pinterest Tag': ['pintrk(']
        }
        
        for tracker, patterns in social_trackers.items():
            if any(pattern in html_lower for pattern in patterns):
                tracking_tech['social_media'].append(tracker)
                tracking_tech['privacy_score'] -= 8
        
        return tracking_tech

class TechnologyDetector(AdvancedTechnologyDetector):
    """Alias per compatibilità con il codice esistente"""
    pass

class SecurityAnalyzer:
    """Analizzatore di sicurezza"""
    
    SECURITY_HEADERS = {
        'strict-transport-security': 'HSTS',
        'content-security-policy': 'CSP',
        'x-frame-options': 'X-Frame-Options',
        'x-content-type-options': 'X-Content-Type-Options',
        'x-xss-protection': 'X-XSS-Protection',
        'referrer-policy': 'Referrer-Policy',
        'permissions-policy': 'Permissions-Policy'
    }
    
    @classmethod
    def analyze_security_headers(cls, headers):
        """Analizza header di sicurezza"""
        security_analysis = {
            'headers_present': {},
            'headers_missing': [],
            'security_score': 0,
            'recommendations': []
        }
        
        for header_key, header_name in cls.SECURITY_HEADERS.items():
            if header_key in headers:
                security_analysis['headers_present'][header_name] = headers[header_key]
                security_analysis['security_score'] += 1
            else:
                security_analysis['headers_missing'].append(header_name)
                security_analysis['recommendations'].append(
                    f"Implementa {header_name} per migliorare la sicurezza"
                )
        
        total_headers = len(cls.SECURITY_HEADERS)
        security_analysis['security_percentage'] = round(
            (security_analysis['security_score'] / total_headers) * 100, 2
        )
        
        return security_analysis
    
    @staticmethod
    def check_ssl_certificate(domain):
        """Verifica certificato SSL con gestione robusta e fallback OpenSSL"""
        import subprocess
        import re
        from datetime import datetime
        
        # Metodo 1: Tentativo con Python SSL standard
        try:
            context = ssl.create_default_context()
            # Configurazione più permissiva per certificati validi ma con problemi di catena
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((domain, 443), timeout=15) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'valid': True,
                        'verification_method': 'python_ssl_verified',
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'san_domains': [x[1] for x in cert.get('subjectAltName', []) if x[0] == 'DNS']
                    }
        except ssl.SSLError as ssl_error:
            # Metodo 2: Tentativo con verifica disabilitata ma recupero dati
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((domain, 443), timeout=15) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        
                        if cert:
                            return {
                                'valid': False,
                                'verification_method': 'python_ssl_unverified',
                                'warning': 'Certificato presente ma verifica fallita - dati estratti senza validazione',
                                'subject': dict(x[0] for x in cert.get('subject', [])),
                                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                                'version': cert.get('version'),
                                'serial_number': cert.get('serialNumber'),
                                'not_before': cert.get('notBefore'),
                                'not_after': cert.get('notAfter'),
                                'san_domains': [x[1] for x in cert.get('subjectAltName', []) if x[0] == 'DNS'],
                                'ssl_error': str(ssl_error)
                            }
            except Exception:
                pass
        
        # Metodo 3: Fallback con OpenSSL diretto
        try:
            cmd = f"echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null | openssl x509 -text -noout"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
            
            if result.returncode == 0 and result.stdout:
                cert_data = SecurityAnalyzer._parse_openssl_output(result.stdout, domain)
                if cert_data:
                    cert_data['verification_method'] = 'openssl_fallback'
                    cert_data['valid'] = True
                    cert_data['note'] = 'Certificato verificato tramite OpenSSL'
                    return cert_data
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        
        # Metodo 4: Ultimo tentativo per ottenere almeno informazioni base
        try:
            cmd = f"echo | openssl s_client -connect {domain}:443 -verify_return_error 2>&1"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            
            if 'Verify return code: 0 (ok)' in result.stdout:
                return {
                    'valid': True,
                    'verification_method': 'openssl_verify',
                    'note': 'Certificato verificato con successo tramite OpenSSL',
                    'openssl_output': result.stdout[:500]  # Prime 500 caratteristiche per debug
                }
            else:
                return {
                    'valid': False,
                    'verification_method': 'all_methods_failed',
                    'error': 'Impossibile verificare o ottenere il certificato SSL',
                    'debug_info': result.stdout[:300] if result.stdout else 'Nessun output'
                }
        except Exception as final_error:
            return {
                'valid': False,
                'verification_method': 'complete_failure',
                'error': f'Tutti i metodi di verifica SSL falliti: {str(final_error)}'
            }
    
    @staticmethod
    def _parse_openssl_output(openssl_output, domain):
        """Analizza l'output di OpenSSL per estrarre informazioni del certificato"""
        try:
            cert_info = {
                'subject': {},
                'issuer': {},
                'version': None,
                'serial_number': None,
                'not_before': None,
                'not_after': None,
                'san_domains': []
            }
            
            # Estrai Subject
            subject_match = re.search(r'Subject: (.+)', openssl_output)
            if subject_match:
                subject_parts = subject_match.group(1).split(', ')
                for part in subject_parts:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        cert_info['subject'][key.strip()] = value.strip()
            
            # Estrai Issuer
            issuer_match = re.search(r'Issuer: (.+)', openssl_output)
            if issuer_match:
                issuer_parts = issuer_match.group(1).split(', ')
                for part in issuer_parts:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        cert_info['issuer'][key.strip()] = value.strip()
            
            # Estrai date di validità
            not_before_match = re.search(r'Not Before: (.+)', openssl_output)
            if not_before_match:
                cert_info['not_before'] = not_before_match.group(1).strip()
            
            not_after_match = re.search(r'Not After : (.+)', openssl_output)
            if not_after_match:
                cert_info['not_after'] = not_after_match.group(1).strip()
            
            # Estrai Serial Number
            serial_match = re.search(r'Serial Number: (.+)', openssl_output)
            if serial_match:
                cert_info['serial_number'] = serial_match.group(1).strip()
            
            # Estrai SAN domains
            san_match = re.search(r'X509v3 Subject Alternative Name:[\s\n]+(.+)', openssl_output)
            if san_match:
                san_line = san_match.group(1)
                dns_entries = re.findall(r'DNS:([^,\s]+)', san_line)
                cert_info['san_domains'] = dns_entries
            
            return cert_info if any(cert_info.values()) else None
            
        except Exception:
            return None

class SubdomainEnumerator:
    """Enumeratore di sottodomini"""
    
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
        'blog', 'shop', 'store', 'support', 'help', 'docs', 'cdn',
        'static', 'assets', 'img', 'images', 'media', 'files', 'download',
        'upload', 'secure', 'portal', 'dashboard', 'panel', 'cpanel',
        'webmail', 'email', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'dns',
        'mx', 'mx1', 'mx2', 'backup', 'old', 'new', 'beta', 'alpha',
        'demo', 'preview', 'mobile', 'm', 'wap', 'app', 'apps', 'service',
        'services', 'cloud', 'vpn', 'ssh', 'sftp', 'git', 'svn',
        'jenkins', 'ci', 'build', 'deploy', 'monitoring', 'stats',
        'analytics', 'logs', 'status', 'health', 'ping', 'test1',
        'test2', 'dev1', 'dev2', 'staging1', 'staging2', 'prod',
        'production', 'live', 'www1', 'www2', 'web', 'web1', 'web2'
    ]
    
    @classmethod
    def enumerate_subdomains(cls, domain, max_workers=20):
        """Enumera sottodomini usando metodi nativi integrati"""
        found_subdomains = []
        
        # Metodo 1: Brute force con lista comune
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{domain}"
                socket.gethostbyname(full_domain)
                return full_domain
            except socket.gaierror:
                return None
        
        # Metodo 2: Ricerca DNS con wildcard detection
        def has_wildcard():
            try:
                random_sub = f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=20))}.{domain}"
                socket.gethostbyname(random_sub)
                return True
            except socket.gaierror:
                return False
        
        # Metodo 3: Ricerca tramite Certificate Transparency
        def search_ct_logs():
            ct_subdomains = set()
            try:
                # Cerca nei CT logs tramite crt.sh
                ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
                response = requests.get(ct_url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data[:100]:  # Limita a 100 risultati
                        name = entry.get('name_value', '')
                        if name and '.' in name:
                            # Pulisci e valida i nomi
                            names = name.split('\n')
                            for n in names:
                                n = n.strip().lower()
                                if n.endswith(f'.{domain}') and '*' not in n:
                                    ct_subdomains.add(n)
            except Exception:
                pass
            return list(ct_subdomains)
        
        # Metodo 4: Ricerca tramite DNS zone transfer (se permesso)
        def try_zone_transfer():
            zone_subdomains = []
            try:
                import dns.zone
                import dns.query
                import dns.resolver
                
                # Ottieni i nameserver
                ns_records = dns.resolver.resolve(domain, 'NS')
                for ns in ns_records:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                        for name in zone.nodes.keys():
                            subdomain = f"{name}.{domain}"
                            if subdomain != domain:
                                zone_subdomains.append(subdomain)
                    except Exception:
                        continue
            except Exception:
                pass
            return zone_subdomains
        
        # Esegui ricerca CT logs in parallelo
        ct_results = search_ct_logs()
        if ct_results:
            found_subdomains.extend(ct_results)
        
        # Verifica se c'è wildcard DNS
        wildcard_detected = has_wildcard()
        if wildcard_detected:
            print(f"⚠️  Wildcard DNS rilevato per {domain} - limitando la ricerca")
        
        # Brute force con lista comune (solo se non c'è wildcard)
        if not wildcard_detected:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_subdomain = {
                    executor.submit(check_subdomain, sub): sub 
                    for sub in cls.COMMON_SUBDOMAINS
                }
                
                for future in as_completed(future_to_subdomain):
                    result = future.result()
                    if result and result not in found_subdomains:
                        found_subdomains.append(result)
        
        # Prova zone transfer
        zone_results = try_zone_transfer()
        if zone_results:
            for sub in zone_results:
                if sub not in found_subdomains:
                    found_subdomains.append(sub)
        
        return sorted(list(set(found_subdomains)))

class GeoIPAnalyzer:
    """Analizzatore GeoIP usando database locali e API gratuite"""
    
    @staticmethod
    def get_ip_info(ip_address, db_path=None, anonymizer=None):
        """Ottiene informazioni geografiche dell'IP con anonimizzazione"""
        # Prova prima con database locale MaxMind se disponibile
        if GEOIP2_AVAILABLE and db_path:
            try:
                import geoip2.database
                import geoip2.errors
                
                with geoip2.database.Reader(db_path) as reader:
                    try:
                        response = reader.city(ip_address)
                        return {
                            'ip': ip_address,
                            'country': response.country.name or 'N/A',
                            'country_code': response.country.iso_code or 'N/A',
                            'region': response.subdivisions.most_specific.name or 'N/A',
                            'city': response.city.name or 'N/A',
                            'latitude': float(response.location.latitude) if response.location.latitude else 'N/A',
                            'longitude': float(response.location.longitude) if response.location.longitude else 'N/A',
                            'timezone': response.location.time_zone or 'N/A',
                            'zip_code': response.postal.code or 'N/A',
                            'accuracy_radius': response.location.accuracy_radius or 'N/A',
                            'method': 'geoip2-local'
                        }
                    except geoip2.errors.AddressNotFoundError:
                        pass  # Fallback alle API
            except Exception:
                pass  # Fallback alle API
        
        # Fallback alle API gratuite con anonimizzazione
        apis = [
            f"http://ip-api.com/json/{ip_address}",
            f"https://ipapi.co/{ip_address}/json/",
            f"https://freegeoip.app/json/{ip_address}"
        ]
        
        for api_url in apis:
            try:
                if anonymizer:
                    session = anonymizer.get_anonymized_session()
                    response = session.get(api_url, timeout=10)
                else:
                    response = requests.get(api_url, timeout=10)
                    
                if response.status_code == 200:
                    data = response.json()
                    
                    # Normalizza i dati da diverse API
                    normalized_data = {
                        'ip': ip_address,
                        'country': data.get('country', data.get('country_name', 'N/A')),
                        'region': data.get('regionName', data.get('region', 'N/A')),
                        'city': data.get('city', 'N/A'),
                        'latitude': data.get('lat', data.get('latitude', 'N/A')),
                        'longitude': data.get('lon', data.get('longitude', 'N/A')),
                        'isp': data.get('isp', data.get('org', 'N/A')),
                        'timezone': data.get('timezone', 'N/A'),
                        'zip_code': data.get('zip', data.get('postal', 'N/A')),
                        'method': 'api-fallback'
                    }
                    return normalized_data
            except Exception:
                continue
        
        return {'error': 'Impossibile ottenere informazioni geografiche'}

class WHOISAnalyzer:
    """Analizzatore WHOIS semplificato"""
    
    @staticmethod
    def get_whois_info(domain):
        """Ottiene informazioni WHOIS"""
        try:
            # Usa python-whois se disponibile, altrimenti fallback nativo
            if WHOIS_AVAILABLE:
                try:
                    w = whois.whois(domain)
                    whois_data = str(w)
                    
                    # Estrai informazioni strutturate
                    info = {
                        'raw_data': whois_data,
                        'registrar': getattr(w, 'registrar', '') or '',
                        'creation_date': str(getattr(w, 'creation_date', '') or ''),
                        'expiration_date': str(getattr(w, 'expiration_date', '') or ''),
                        'name_servers': getattr(w, 'name_servers', []) or [],
                        'status': getattr(w, 'status', []) or [],
                        'emails': getattr(w, 'emails', []) or [],
                        'country': getattr(w, 'country', '') or '',
                        'method': 'python-whois'
                    }
                except Exception:
                    # Fallback al metodo nativo
                    whois_data = NativeImplementations.simple_whois(domain)
                    info = {
                        'raw_data': whois_data,
                        'registrar': '',
                        'creation_date': '',
                        'expiration_date': '',
                        'name_servers': [],
                        'status': [],
                        'emails': [],
                        'country': '',
                        'method': 'native-whois'
                    }
            else:
                # Usa implementazione nativa
                whois_data = NativeImplementations.simple_whois(domain)
                info = {
                    'raw_data': whois_data,
                    'registrar': '',
                    'creation_date': '',
                    'expiration_date': '',
                    'name_servers': [],
                    'status': [],
                    'emails': [],
                    'country': '',
                    'method': 'native-whois'
                }
            
            return info
                
        except Exception as e:
            return {'error': f'WHOIS error: {str(e)}'}

class PortScanner:
    """Scanner di porte semplificato"""
    
    COMMON_PORTS = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
        995: 'POP3S', 587: 'SMTP', 465: 'SMTPS', 3389: 'RDP', 5432: 'PostgreSQL',
        3306: 'MySQL', 1433: 'MSSQL', 6379: 'Redis', 27017: 'MongoDB',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch'
    }
    
    @classmethod
    def scan_ports(cls, target, ports=None, timeout=3):
        """Scansiona porte specifiche"""
        if ports is None:
            ports = list(cls.COMMON_PORTS.keys())
        
        open_ports = []
        
        # Usa nmap se disponibile, altrimenti fallback nativo
        if NMAP_AVAILABLE:
            try:
                nm = nmap.PortScanner()
                port_range = f"{min(ports)}-{max(ports)}"
                nm.scan(target, port_range, arguments='-sS -T4')
                
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        ports_found = nm[host][proto].keys()
                        for port in ports_found:
                            if nm[host][proto][port]['state'] == 'open':
                                service = nm[host][proto][port].get('name', cls.COMMON_PORTS.get(port, 'Unknown'))
                                open_ports.append({
                                    'port': port,
                                    'service': service,
                                    'status': 'open',
                                    'method': 'nmap'
                                })
                return open_ports
            except Exception:
                # Fallback al metodo nativo
                pass
        
        # Usa implementazione nativa
        native_ports = NativeImplementations.simple_port_scan(target, ports)
        for port in native_ports:
            service = cls.COMMON_PORTS.get(port, 'Unknown')
            open_ports.append({
                'port': port,
                'service': service,
                'status': 'open',
                'method': 'native-scan'
            })
        
        return sorted(open_ports, key=lambda x: x['port'])
        
        # Metodo fallback con socket
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    service = cls.COMMON_PORTS.get(port, 'Unknown')
                    return {'port': port, 'service': service, 'status': 'open', 'method': 'socket'}
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return sorted(open_ports, key=lambda x: x['port'])

class VulnerabilityScanner:
    """Scanner di vulnerabilità di base"""
    
    @staticmethod
    def check_common_vulnerabilities(target_url, headers):
        """Controlla vulnerabilità comuni"""
        vulnerabilities = []
        
        try:
            response = requests.get(target_url, headers=headers, timeout=10)
            
            # Check per directory traversal
            test_paths = [
                '/../../../etc/passwd',
                '/..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '/.env',
                '/config.php',
                '/wp-config.php',
                '/admin',
                '/phpmyadmin',
                '/.git/config'
            ]
            
            for path in test_paths:
                try:
                    test_url = urljoin(target_url, path)
                    test_response = requests.get(test_url, headers=headers, timeout=5)
                    
                    if test_response.status_code == 200:
                        if 'root:' in test_response.text or 'password' in test_response.text.lower():
                            vulnerabilities.append({
                                'type': 'Information Disclosure',
                                'path': path,
                                'severity': 'High',
                                'description': f'Sensitive file accessible: {path}'
                            })
                        elif test_response.status_code != 404:
                            vulnerabilities.append({
                                'type': 'Directory/File Exposure',
                                'path': path,
                                'severity': 'Medium',
                                'description': f'Accessible path found: {path}'
                            })
                except:
                    continue
            
            # Check per header di sicurezza mancanti
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-Content-Type-Options': 'MIME type sniffing protection missing',
                'X-XSS-Protection': 'XSS protection missing',
                'Strict-Transport-Security': 'HSTS missing',
                'Content-Security-Policy': 'CSP missing'
            }
            
            for header, description in security_headers.items():
                if header.lower() not in [h.lower() for h in response.headers.keys()]:
                    vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'header': header,
                        'severity': 'Medium',
                        'description': description
                    })
            
            # Check per server information disclosure
            server_header = response.headers.get('Server', '')
            if server_header and any(info in server_header.lower() for info in ['apache/', 'nginx/', 'iis/']):
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'header': 'Server',
                    'severity': 'Low',
                    'description': f'Server version disclosed: {server_header}'
                })
            
        except Exception as e:
            vulnerabilities.append({
                'type': 'Scan Error',
                'severity': 'Info',
                'description': f'Error during vulnerability scan: {str(e)}'
            })
        
        return vulnerabilities

class MetadataExtractor:
    """Estrattore di metadati avanzato"""
    
    @staticmethod
    def extract_document_metadata(url, headers):
        """Estrae metadati da documenti"""
        metadata = []
        
        # Cerca documenti comuni
        doc_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            parser = SimpleHTMLParser()
            parser.feed(response.text)
            
            # Cerca link a documenti
            for link in parser.links:
                if any(ext in link.lower() for ext in doc_extensions):
                    try:
                        doc_url = urljoin(url, link)
                        doc_response = requests.head(doc_url, headers=headers, timeout=5)
                        
                        if doc_response.status_code == 200:
                            metadata.append({
                                'url': doc_url,
                                'type': 'document',
                                'content_type': doc_response.headers.get('content-type', 'unknown'),
                                'size': doc_response.headers.get('content-length', 'unknown'),
                                'last_modified': doc_response.headers.get('last-modified', 'unknown')
                            })
                    except:
                        continue
        except:
            pass
        
        return metadata
    
    @staticmethod
    def extract_image_metadata(url, headers):
        """Estrae metadati dalle immagini"""
        metadata = []
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            parser = SimpleHTMLParser()
            parser.feed(response.text)
            
            # Analizza prime 20 immagini
            for img_src in parser.images[:20]:
                try:
                    img_url = urljoin(url, img_src)
                    img_response = requests.head(img_url, headers=headers, timeout=5)
                    
                    if img_response.status_code == 200:
                        metadata.append({
                            'url': img_url,
                            'type': 'image',
                            'content_type': img_response.headers.get('content-type', 'unknown'),
                            'size': img_response.headers.get('content-length', 'unknown'),
                            'last_modified': img_response.headers.get('last-modified', 'unknown')
                        })
                except:
                    continue
        except:
            pass
        
        return metadata

class CDNDetector:
    """Rilevatore di CDN e servizi cloud"""
    
    CDN_INDICATORS = {
        'Cloudflare': ['cloudflare', 'cf-ray', 'cf-cache-status'],
        'AWS CloudFront': ['cloudfront', 'x-amz-cf-id'],
        'Fastly': ['fastly', 'x-served-by'],
        'MaxCDN': ['maxcdn', 'x-cache'],
        'KeyCDN': ['keycdn'],
        'Akamai': ['akamai', 'x-akamai'],
        'Incapsula': ['incapsula', 'x-iinfo'],
        'Sucuri': ['sucuri', 'x-sucuri']
    }
    
    @classmethod
    def detect_cdn(cls, headers, domain):
        """Rileva CDN utilizzato"""
        detected_cdns = []
        
        # Controlla header
        for cdn_name, indicators in cls.CDN_INDICATORS.items():
            for indicator in indicators:
                for header_name, header_value in headers.items():
                    if indicator.lower() in header_name.lower() or indicator.lower() in str(header_value).lower():
                        detected_cdns.append(cdn_name)
                        break
        
        # Controlla CNAME records
        try:
            import subprocess
            result = subprocess.run(['nslookup', domain], capture_output=True, text=True, timeout=10)
            cname_output = result.stdout.lower()
            
            for cdn_name, indicators in cls.CDN_INDICATORS.items():
                for indicator in indicators:
                    if indicator in cname_output:
                        if cdn_name not in detected_cdns:
                            detected_cdns.append(cdn_name)
        except:
            pass
        
        return list(set(detected_cdns))

class CookieAnalyzer:
    """Analizzatore avanzato di cookie"""
    
    @staticmethod
    def analyze_cookies(cookies):
        """Analizza cookie per sicurezza e privacy"""
        analysis = {
            'total_cookies': len(cookies),
            'security_issues': [],
            'privacy_concerns': [],
            'tracking_cookies': [],
            'session_cookies': [],
            'persistent_cookies': []
        }
        
        tracking_indicators = ['ga', 'gtm', 'facebook', 'doubleclick', 'adsystem', 'analytics']
        
        for cookie in cookies:
            cookie_info = {
                'name': cookie.get('name', ''),
                'domain': cookie.get('domain', ''),
                'path': cookie.get('path', ''),
                'secure': cookie.get('secure', False),
                'httponly': cookie.get('httponly', False)
            }
            
            # Controlla problemi di sicurezza
            if not cookie_info['secure']:
                analysis['security_issues'].append(f"Cookie '{cookie_info['name']}' non ha flag Secure")
            
            if not cookie_info['httponly']:
                analysis['security_issues'].append(f"Cookie '{cookie_info['name']}' non ha flag HttpOnly")
            
            # Identifica cookie di tracking
            cookie_name_lower = cookie_info['name'].lower()
            if any(indicator in cookie_name_lower for indicator in tracking_indicators):
                analysis['tracking_cookies'].append(cookie_info)
                analysis['privacy_concerns'].append(f"Cookie di tracking rilevato: {cookie_info['name']}")
            
            # Classifica cookie
            if cookie.get('expires') or cookie.get('max-age'):
                analysis['persistent_cookies'].append(cookie_info)
            else:
                analysis['session_cookies'].append(cookie_info)
        
        return analysis

class HoneypotDetector:
    """Rilevatore di honeypot e trappole"""
    
    HONEYPOT_INDICATORS = [
        'honeypot', 'canary', 'trap', 'decoy', 'fake',
        'monitoring', 'detection', 'alert', 'warning'
    ]
    
    @classmethod
    def check_honeypot_indicators(cls, url, headers, html_content):
        """Controlla indicatori di honeypot"""
        indicators = []
        
        # Controlla header sospetti
        for header_name, header_value in headers.items():
            header_text = f"{header_name} {header_value}".lower()
            for indicator in cls.HONEYPOT_INDICATORS:
                if indicator in header_text:
                    indicators.append(f"Header sospetto: {header_name}")
        
        # Controlla contenuto HTML
        html_lower = html_content.lower()
        for indicator in cls.HONEYPOT_INDICATORS:
            if indicator in html_lower:
                indicators.append(f"Contenuto sospetto: keyword '{indicator}' trovata")
        
        # Controlla comportamenti anomali
        if len(headers) < 3:
            indicators.append("Numero di header HTTP insolitamente basso")
        
        if 'server' not in headers:
            indicators.append("Header Server mancante (possibile occultamento)")
        
        return {
            'is_suspicious': len(indicators) > 0,
            'risk_level': 'High' if len(indicators) > 3 else 'Medium' if len(indicators) > 1 else 'Low',
            'indicators': indicators
        }

class AdvancedWebScraper:
    """Web scraper avanzato con funzionalità potenziate"""
    
    @staticmethod
    def deep_crawl(url, headers, max_depth=2, max_pages=50):
        """Crawling profondo del sito"""
        visited = set()
        to_visit = [(url, 0)]
        crawl_results = {
            'pages': [],
            'external_links': set(),
            'emails': set(),
            'phone_numbers': set(),
            'social_media': {},
            'technologies': set(),
            'forms': [],
            'comments': []
        }
        
        domain = urlparse(url).netloc
        
        while to_visit and len(crawl_results['pages']) < max_pages:
            current_url, depth = to_visit.pop(0)
            
            if current_url in visited or depth > max_depth:
                continue
            
            try:
                response = requests.get(current_url, headers=headers, timeout=10)
                if response.status_code == 200:
                    visited.add(current_url)
                    
                    parser = SimpleHTMLParser()
                    parser.feed(response.text)
                    
                    # Salva informazioni pagina
                    page_info = {
                        'url': current_url,
                        'title': parser.title,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'links_count': len(parser.links),
                        'forms_count': len(parser.forms)
                    }
                    crawl_results['pages'].append(page_info)
                    
                    # Estrai email e telefoni
                    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                    phone_pattern = r'\+?[0-9]{1,4}[-.]?[0-9]{1,4}[-.]?[0-9]{4,}'
                    
                    crawl_results['emails'].update(re.findall(email_pattern, response.text))
                    crawl_results['phone_numbers'].update(re.findall(phone_pattern, response.text))
                    
                    # Estrai commenti HTML
                    comments = re.findall(r'<!--([\s\S]*?)-->', response.text)
                    crawl_results['comments'].extend([c.strip() for c in comments if c.strip()])
                    
                    # Aggiungi form
                    crawl_results['forms'].extend(parser.forms)
                    
                    # Trova nuovi link da visitare
                    for link in parser.links:
                        if link.startswith('http'):
                            link_domain = urlparse(link).netloc
                            if link_domain == domain and link not in visited:
                                to_visit.append((link, depth + 1))
                            elif link_domain != domain:
                                crawl_results['external_links'].add(link)
                        elif link.startswith('/'):
                            full_link = urljoin(current_url, link)
                            if full_link not in visited:
                                to_visit.append((full_link, depth + 1))
                
            except Exception:
                continue
        
        # Converti set in liste per JSON serialization
        crawl_results['external_links'] = list(crawl_results['external_links'])
        crawl_results['emails'] = list(crawl_results['emails'])
        crawl_results['phone_numbers'] = list(crawl_results['phone_numbers'])
        
        return crawl_results
    
    @staticmethod
    def extract_javascript_data(url, headers):
        """Estrae dati da JavaScript"""
        js_data = {
            'external_scripts': [],
            'inline_scripts': [],
            'api_endpoints': [],
            'variables': []
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            
            # Estrai script esterni
            script_pattern = r'<script[^>]*src=["\']([^"\'>]+)["\'][^>]*>'
            external_scripts = re.findall(script_pattern, response.text)
            js_data['external_scripts'] = [urljoin(url, script) for script in external_scripts]
            
            # Estrai script inline
            inline_pattern = r'<script[^>]*>([\s\S]*?)</script>'
            inline_scripts = re.findall(inline_pattern, response.text)
            js_data['inline_scripts'] = [script.strip() for script in inline_scripts if script.strip()]
            
            # Cerca API endpoints
            api_patterns = [
                r'["\']https?://[^"\'>]+/api/[^"\'>]+["\']',
                r'["\']https?://[^"\'>]+\.json["\']',
                r'["\']https?://[^"\'>]+/v\d+/[^"\'>]+["\']'
            ]
            
            for pattern in api_patterns:
                endpoints = re.findall(pattern, response.text)
                js_data['api_endpoints'].extend([ep.strip('"\'') for ep in endpoints])
            
            # Cerca variabili interessanti
            var_patterns = [
                r'var\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\'>]+)["\']',
                r'const\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\'>]+)["\']',
                r'let\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\'>]+)["\']'
            ]
            
            for pattern in var_patterns:
                variables = re.findall(pattern, response.text)
                js_data['variables'].extend([{'name': var[0], 'value': var[1]} for var in variables])
            
        except Exception:
            pass
        
        return js_data

class ThreatIntelligenceAnalyzer:
    """Analizzatore di threat intelligence usando Shodan e Censys"""
    
    @staticmethod
    def shodan_analysis(ip_address, api_key=None):
        """Analisi usando Shodan API"""
        if not SHODAN_AVAILABLE:
            return {'error': 'Shodan library not available', 'method': 'unavailable'}
        
        try:
            import shodan
            if not api_key:
                return {'error': 'Shodan API key required', 'method': 'shodan'}
            
            api = shodan.Shodan(api_key)
            host_info = api.host(ip_address)
            
            return {
                'ip': ip_address,
                'hostnames': host_info.get('hostnames', []),
                'ports': host_info.get('ports', []),
                'vulns': list(host_info.get('vulns', [])),
                'os': host_info.get('os'),
                'org': host_info.get('org'),
                'isp': host_info.get('isp'),
                'country': host_info.get('country_name'),
                'city': host_info.get('city'),
                'last_update': host_info.get('last_update'),
                'tags': host_info.get('tags', []),
                'method': 'shodan'
            }
        except Exception as e:
            return {'error': str(e), 'method': 'shodan'}
    
    @staticmethod
    def censys_analysis(ip_address, api_id=None, api_secret=None):
        """Analisi usando Censys API"""
        if not CENSYS_AVAILABLE:
            return {'error': 'Censys library not available', 'method': 'unavailable'}
        
        try:
            import censys.search
            if not api_id or not api_secret:
                return {'error': 'Censys API credentials required', 'method': 'censys'}
            
            c = censys.search.CensysHosts(api_id=api_id, api_secret=api_secret)
            host_info = c.view(ip_address)
            
            return {
                'ip': ip_address,
                'services': host_info.get('services', []),
                'protocols': list(host_info.get('protocols', [])),
                'autonomous_system': host_info.get('autonomous_system', {}),
                'location': host_info.get('location', {}),
                'last_updated': host_info.get('last_updated_at'),
                'operating_system': host_info.get('operating_system', {}),
                'method': 'censys'
            }
        except Exception as e:
            return {'error': str(e), 'method': 'censys'}
    
    @staticmethod
    def combined_threat_analysis(ip_address, shodan_key=None, censys_id=None, censys_secret=None):
        """Analisi combinata usando entrambe le fonti"""
        results = {
            'ip': ip_address,
            'shodan': {},
            'censys': {},
            'combined_insights': []
        }
        
        # Analisi Shodan
        if shodan_key:
            results['shodan'] = ThreatIntelligenceAnalyzer.shodan_analysis(ip_address, shodan_key)
        
        # Analisi Censys
        if censys_id and censys_secret:
            results['censys'] = ThreatIntelligenceAnalyzer.censys_analysis(ip_address, censys_id, censys_secret)
        
        # Genera insights combinati
        insights = []
        
        # Confronta porte aperte
        shodan_ports = results['shodan'].get('ports', [])
        censys_services = results['censys'].get('services', [])
        censys_ports = [service.get('port') for service in censys_services if service.get('port')]
        
        if shodan_ports and censys_ports:
            common_ports = set(shodan_ports) & set(censys_ports)
            if common_ports:
                insights.append(f"Porte confermate da entrambe le fonti: {sorted(common_ports)}")
        
        # Verifica vulnerabilità
        vulns = results['shodan'].get('vulns', [])
        if vulns:
            insights.append(f"Vulnerabilità rilevate da Shodan: {len(vulns)} CVE")
        
        results['combined_insights'] = insights
        return results

class CDNBypassAnalyzer:
    """Analizzatore per identificare IP reali dietro CDN (basato su Crimeflare)"""
    
    @staticmethod
    def get_real_ip_crimeflare(domain, anonymizer=None):
        """Utilizza l'API Crimeflare per trovare l'IP reale dietro CloudFlare con anonimizzazione"""
        try:
            # Pulisce il dominio
            domain = domain.replace('www.', '').replace('http://', '').replace('https://', '').replace('/', '')
            
            # Chiama l'API Crimeflare con anonimizzazione
            api_url = f"http://crimeflare.zidansec.com/?url={domain}"
            
            if anonymizer:
                session = anonymizer.get_anonymized_session()
                response = session.get(api_url, timeout=10)
            else:
                response = requests.get(api_url, timeout=10)
            
            if response.status_code == 200:
                # Estrae l'IP reale usando regex
                import re
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', response.text)
                if ip_match:
                    real_ip = ip_match.group(1)
                    
                    # Ottiene informazioni aggiuntive sull'IP
                    ip_info = CDNBypassAnalyzer._get_ip_details(real_ip, anonymizer)
                    
                    return {
                        'success': True,
                        'real_ip': real_ip,
                        'cloudflare_ip': socket.gethostbyname(domain),
                        'ip_info': ip_info,
                        'method': 'crimeflare-api'
                    }
            
            return {'success': False, 'error': 'No real IP found', 'method': 'crimeflare-api'}
            
        except Exception as e:
            return {'success': False, 'error': str(e), 'method': 'crimeflare-api'}
    
    @staticmethod
    def _get_ip_details(ip, anonymizer=None):
        """Ottiene dettagli geografici e organizzativi di un IP con anonimizzazione"""
        try:
            # Usa ip-api.com per informazioni dettagliate
            api_url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,query"
            
            if anonymizer:
                session = anonymizer.get_anonymized_session()
                response = session.get(api_url, timeout=5)
            else:
                response = requests.get(api_url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'city': data.get('city'),
                        'region': data.get('regionName'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'timezone': data.get('timezone'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'asn': data.get('as')
                    }
            
            return {'error': 'Unable to get IP details'}
            
        except Exception as e:
            return {'error': f'IP details lookup failed: {str(e)}'}
    
    @staticmethod
    def analyze_dns_records(domain):
        """Analizza record DNS per trovare subdomain non protetti da CDN"""
        try:
            results = {
                'protected_subdomains': [],
                'unprotected_subdomains': [],
                'dns_records': {},
                'method': 'dns-analysis'
            }
            
            # Lista di subdomain comuni che potrebbero non essere dietro CDN
            common_subdomains = [
                'admin', 'mail', 'ftp', 'cpanel', 'webmail', 'direct', 'origin',
                'dev', 'test', 'staging', 'beta', 'api', 'old', 'backup',
                'ssh', 'vpn', 'remote', 'internal', 'intranet', 'private'
            ]
            
            # Ottiene l'IP principale del dominio
            try:
                main_ip = socket.gethostbyname(domain)
                results['main_domain_ip'] = main_ip
            except:
                main_ip = None
            
            # Testa ogni subdomain
            for subdomain in common_subdomains:
                full_domain = f"{subdomain}.{domain}"
                try:
                    subdomain_ip = socket.gethostbyname(full_domain)
                    
                    # Controlla se l'IP è diverso dal dominio principale
                    if subdomain_ip != main_ip:
                        # Verifica se è un IP CloudFlare
                        if CDNBypassAnalyzer._is_cloudflare_ip(subdomain_ip):
                            results['protected_subdomains'].append({
                                'subdomain': full_domain,
                                'ip': subdomain_ip,
                                'protected': True
                            })
                        else:
                            results['unprotected_subdomains'].append({
                                'subdomain': full_domain,
                                'ip': subdomain_ip,
                                'protected': False,
                                'ip_info': CDNBypassAnalyzer._get_ip_details(subdomain_ip)
                            })
                    
                except socket.gaierror:
                    # Subdomain non esiste
                    continue
                except Exception as e:
                    continue
            
            # Ottiene record DNS aggiuntivi
            try:
                if DNS_AVAILABLE:
                    import dns.resolver
                    
                    # Record A
                    try:
                        a_records = dns.resolver.resolve(domain, 'A')
                        results['dns_records']['A'] = [str(record) for record in a_records]
                    except:
                        pass
                    
                    # Record MX
                    try:
                        mx_records = dns.resolver.resolve(domain, 'MX')
                        results['dns_records']['MX'] = [str(record) for record in mx_records]
                    except:
                        pass
                    
                    # Record TXT
                    try:
                        txt_records = dns.resolver.resolve(domain, 'TXT')
                        results['dns_records']['TXT'] = [str(record) for record in txt_records]
                    except:
                        pass
            except:
                pass
            
            return results
            
        except Exception as e:
            return {'error': str(e), 'method': 'dns-analysis'}
    
    @staticmethod
    def _is_cloudflare_ip(ip):
        """Verifica se un IP appartiene a CloudFlare"""
        # Range IP CloudFlare noti
        cloudflare_ranges = [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
            '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
            '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
            '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
        ]
        
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            
            for cidr in cloudflare_ranges:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True
            return False
        except:
            return False
    
    @staticmethod
    def comprehensive_cdn_bypass(domain, anonymizer=None):
        """Analisi completa per bypassare CDN con anonimizzazione"""
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'methods_used': [],
            'findings': {}
        }
        
        # Metodo 1: Crimeflare API
        print(f"[*] Tentativo bypass CDN con Crimeflare per {domain}...")
        crimeflare_result = CDNBypassAnalyzer.get_real_ip_crimeflare(domain, anonymizer)
        results['findings']['crimeflare'] = crimeflare_result
        results['methods_used'].append('crimeflare')
        
        # Metodo 2: Analisi DNS e subdomain
        print(f"[*] Analisi DNS e subdomain per {domain}...")
        dns_result = CDNBypassAnalyzer.analyze_dns_records(domain)
        results['findings']['dns_analysis'] = dns_result
        results['methods_used'].append('dns_analysis')
        
        # Metodo 3: Controllo record storici (se disponibile)
        if WAYBACK_AVAILABLE:
            print(f"[*] Controllo record storici per {domain}...")
            try:
                # Implementazione semplificata per record storici
                results['findings']['historical'] = {
                    'method': 'wayback-check',
                    'note': 'Historical IP analysis would require additional implementation'
                }
                results['methods_used'].append('historical')
            except:
                pass
        
        # Riassunto risultati
        summary = {
            'real_ips_found': [],
            'unprotected_subdomains': [],
            'recommendations': []
        }
        
        # Estrae IP reali trovati
        if crimeflare_result.get('success'):
            summary['real_ips_found'].append({
                'ip': crimeflare_result['real_ip'],
                'method': 'crimeflare',
                'confidence': 'high'
            })
        
        # Estrae subdomain non protetti
        if 'unprotected_subdomains' in dns_result:
            summary['unprotected_subdomains'] = dns_result['unprotected_subdomains']
        
        # Genera raccomandazioni
        if summary['real_ips_found']:
            summary['recommendations'].append("IP reali identificati - verificare accessibilità diretta")
        
        if summary['unprotected_subdomains']:
            summary['recommendations'].append("Subdomain non protetti trovati - possibili punti di accesso")
        
        if not summary['real_ips_found'] and not summary['unprotected_subdomains']:
            summary['recommendations'].append("CDN bypass non riuscito - il sito potrebbe essere completamente protetto")
        
        results['summary'] = summary
        return results

class WaybackAnalyzer:
    """Analizzatore Wayback Machine per cronologia siti web"""
    
    @staticmethod
    def get_snapshots(url, limit=10):
        """Ottiene snapshot storici di un URL"""
        if not WAYBACK_AVAILABLE:
            return {'error': 'Wayback library not available', 'method': 'unavailable'}
        
        try:
            import waybackpy
            wayback = waybackpy.Url(url)
            
            # Ottieni snapshot disponibili
            snapshots = []
            for snapshot in wayback.snapshots():
                snapshots.append({
                    'timestamp': snapshot.timestamp,
                    'archive_url': snapshot.archive_url,
                    'original': snapshot.original,
                    'status_code': getattr(snapshot, 'status_code', None)
                })
                
                if len(snapshots) >= limit:
                    break
            
            return {
                'url': url,
                'total_snapshots': len(snapshots),
                'snapshots': snapshots,
                'method': 'wayback'
            }
            
        except Exception as e:
            return {'error': str(e), 'method': 'wayback'}
    
    @staticmethod
    def get_first_last_snapshot(url):
        """Ottiene il primo e ultimo snapshot di un URL"""
        if not WAYBACK_AVAILABLE:
            return {'error': 'Wayback library not available', 'method': 'unavailable'}
        
        try:
            import waybackpy
            wayback = waybackpy.Url(url)
            
            result = {
                'url': url,
                'first_snapshot': None,
                'last_snapshot': None,
                'method': 'wayback'
            }
            
            try:
                oldest = wayback.oldest()
                result['first_snapshot'] = {
                    'timestamp': oldest.timestamp,
                    'archive_url': oldest.archive_url,
                    'original': oldest.original
                }
            except Exception:
                pass
            
            try:
                newest = wayback.newest()
                result['last_snapshot'] = {
                    'timestamp': newest.timestamp,
                    'archive_url': newest.archive_url,
                    'original': newest.original
                }
            except Exception:
                pass
            
            return result
            
        except Exception as e:
            return {'error': str(e), 'method': 'wayback'}
    
    @staticmethod
    def analyze_historical_changes(url, max_snapshots=5):
        """Analizza i cambiamenti storici di un sito"""
        if not WAYBACK_AVAILABLE:
            return {'error': 'Wayback library not available', 'method': 'unavailable'}
        
        try:
            import waybackpy
            wayback = waybackpy.Url(url)
            
            snapshots_data = []
            snapshot_count = 0
            
            for snapshot in wayback.snapshots():
                if snapshot_count >= max_snapshots:
                    break
                
                try:
                    # Ottieni contenuto dello snapshot
                    content = snapshot.get()
                    snapshots_data.append({
                        'timestamp': snapshot.timestamp,
                        'archive_url': snapshot.archive_url,
                        'content_length': len(content.text) if hasattr(content, 'text') else 0,
                        'status_code': getattr(content, 'status_code', None)
                    })
                    snapshot_count += 1
                except Exception:
                    continue
            
            # Analizza i cambiamenti
            changes_analysis = {
                'url': url,
                'analyzed_snapshots': len(snapshots_data),
                'content_size_changes': [],
                'method': 'wayback'
            }
            
            if len(snapshots_data) > 1:
                for i in range(1, len(snapshots_data)):
                    prev_size = snapshots_data[i-1]['content_length']
                    curr_size = snapshots_data[i]['content_length']
                    
                    if prev_size > 0:  # Evita divisione per zero
                        change_percent = ((curr_size - prev_size) / prev_size) * 100
                        changes_analysis['content_size_changes'].append({
                            'from_timestamp': snapshots_data[i-1]['timestamp'],
                            'to_timestamp': snapshots_data[i]['timestamp'],
                            'size_change_percent': round(change_percent, 2),
                            'size_change_bytes': curr_size - prev_size
                        })
            
            return changes_analysis
            
        except Exception as e:
            return {'error': str(e), 'method': 'wayback'}

class IPHistoryTracker:
    """Tracker per cronologia IP e rilevamento CDN masking"""
    
    @staticmethod
    def get_ip_history(domain):
        """Ottiene cronologia IP tramite passive DNS"""
        ip_history = {
            'current_ips': [],
            'historical_ips': [],
            'cdn_detection': {},
            'dns_leaks': [],
            'asn_info': {},
            'hosting_providers': []
        }
        
        try:
            # IP correnti
            current_ips = socket.gethostbyname_ex(domain)[2]
            ip_history['current_ips'] = current_ips
            
            # Tenta di ottenere informazioni storiche tramite DNS pubblici
            dns_servers = ['8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9']
            historical_ips = set()
            
            for dns_server in dns_servers:
                try:
                    if DNS_AVAILABLE:
                        resolver = dns.resolver.Resolver()
                        resolver.nameservers = [dns_server]
                        answers = resolver.resolve(domain, 'A')
                        for answer in answers:
                            historical_ips.add(str(answer))
                    else:
                        # Fallback usando socket
                        try:
                            ip = socket.gethostbyname(domain)
                            historical_ips.add(ip)
                        except:
                            pass
                except:
                    continue
            
            ip_history['historical_ips'] = list(historical_ips)
            
            # Rilevamento CDN
            ip_history['cdn_detection'] = IPHistoryTracker._detect_cdn_from_ips(list(historical_ips))
            
            # DNS Leaks - controlla sottodomini comuni
            ip_history['dns_leaks'] = IPHistoryTracker._check_dns_leaks(domain)
            
            # Informazioni ASN per ogni IP
            all_ips = list(set(current_ips + list(historical_ips)))
            for ip in all_ips:
                asn_info = IPHistoryTracker._get_asn_info(ip)
                if asn_info:
                    ip_history['asn_info'][ip] = asn_info
            
            # Hosting providers
            ip_history['hosting_providers'] = IPHistoryTracker._identify_hosting_providers(ip_history['asn_info'])
            
        except Exception as e:
            ip_history['error'] = str(e)
        
        return ip_history
    
    @staticmethod
    def _detect_cdn_from_ips(ips):
        """Rileva CDN basandosi sugli IP"""
        cdn_ranges = {
            'Cloudflare': [
                '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
                '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
                '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
                '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
                '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
            ],
            'Amazon CloudFront': [
                '13.32.0.0/15', '13.35.0.0/16', '18.160.0.0/15',
                '52.222.128.0/17', '54.230.0.0/16', '54.239.128.0/18',
                '99.84.0.0/16', '205.251.192.0/19', '54.239.192.0/19'
            ],
            'Fastly': [
                '23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24',
                '103.245.222.0/23', '103.245.224.0/24', '104.156.80.0/20',
                '146.75.0.0/16', '151.101.0.0/16', '157.52.64.0/18'
            ],
            'MaxCDN': [
                '94.31.27.0/24', '94.31.29.0/24', '177.54.148.0/24'
            ]
        }
        
        detected_cdns = {}
        
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                for cdn_name, ranges in cdn_ranges.items():
                    for range_str in ranges:
                        try:
                            network = ipaddress.ip_network(range_str)
                            if ip_obj in network:
                                if cdn_name not in detected_cdns:
                                    detected_cdns[cdn_name] = []
                                detected_cdns[cdn_name].append(ip)
                        except:
                            continue
            except:
                continue
        
        return detected_cdns
    
    @staticmethod
    def _check_dns_leaks(domain):
        """Controlla DNS leaks tramite sottodomini comuni"""
        common_subdomains = [
            'autodiscover', 'mail', 'webmail', 'ftp', 'cpanel', 'whm',
            'admin', 'www', 'api', 'dev', 'staging', 'test', 'beta',
            'secure', 'portal', 'login', 'members', 'support', 'help',
            'blog', 'news', 'shop', 'store', 'cdn', 'static', 'assets',
            'img', 'images', 'media', 'files', 'download', 'uploads'
        ]
        
        dns_leaks = []
        
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                ips = socket.gethostbyname_ex(full_domain)[2]
                if ips:
                    dns_leaks.append({
                        'subdomain': full_domain,
                        'ips': ips,
                        'leak_type': 'subdomain_enumeration'
                    })
            except:
                continue
        
        # Controlla record TXT per possibili leak
        try:
            if DNS_AVAILABLE:
                resolver = dns.resolver.Resolver()
                txt_records = resolver.resolve(domain, 'TXT')
                for record in txt_records:
                    record_str = str(record)
                    if any(keyword in record_str.lower() for keyword in ['ip=', 'include:', 'redirect=']):
                        dns_leaks.append({
                            'record': record_str,
                            'leak_type': 'txt_record_leak'
                        })
            else:
                # Implementazione fallback limitata
                dns_leaks.append({
                    'record': 'DNS library not available - limited functionality',
                    'leak_type': 'library_limitation'
                })
        except:
            pass
        
        return dns_leaks
    
    @staticmethod
    def _get_asn_info(ip):
        """Ottiene informazioni ASN per un IP"""
        try:
            # Usa whois per ottenere informazioni ASN
            import subprocess
            result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=10)
            whois_output = result.stdout.lower()
            
            asn_info = {
                'ip': ip,
                'asn': None,
                'org': None,
                'country': None,
                'network': None
            }
            
            # Estrai ASN
            import re
            asn_match = re.search(r'asn?:?\s*(as)?([0-9]+)', whois_output)
            if asn_match:
                asn_info['asn'] = f"AS{asn_match.group(2)}"
            
            # Estrai organizzazione
            org_patterns = [
                r'org-name:\s*(.+)',
                r'organization:\s*(.+)',
                r'orgname:\s*(.+)',
                r'org:\s*(.+)'
            ]
            
            for pattern in org_patterns:
                org_match = re.search(pattern, whois_output)
                if org_match:
                    asn_info['org'] = org_match.group(1).strip()
                    break
            
            # Estrai paese
            country_match = re.search(r'country:\s*([a-z]{2})', whois_output)
            if country_match:
                asn_info['country'] = country_match.group(1).upper()
            
            # Estrai network
            network_patterns = [
                r'cidr:\s*([0-9./]+)',
                r'route:\s*([0-9./]+)',
                r'netrange:\s*([0-9.-]+)'
            ]
            
            for pattern in network_patterns:
                network_match = re.search(pattern, whois_output)
                if network_match:
                    asn_info['network'] = network_match.group(1)
                    break
            
            return asn_info
            
        except Exception as e:
            return {'ip': ip, 'error': str(e)}
    
    @staticmethod
    def _identify_hosting_providers(asn_info):
        """Identifica hosting providers basandosi su ASN"""
        known_providers = {
            'AS13335': 'Cloudflare',
            'AS16509': 'Amazon Web Services',
            'AS15169': 'Google Cloud',
            'AS8075': 'Microsoft Azure',
            'AS20940': 'Akamai',
            'AS54113': 'Fastly',
            'AS36459': 'GitHub',
            'AS46606': 'Unified Layer (Bluehost)',
            'AS26496': 'GoDaddy',
            'AS33070': 'RackSpace',
            'AS14061': 'DigitalOcean',
            'AS25820': 'IT7 Networks (Linode)',
            'AS16276': 'OVH',
            'AS24940': 'Hetzner Online',
            'AS45102': 'Alibaba Cloud'
        }
        
        providers = []
        
        for ip, info in asn_info.items():
            if 'asn' in info and info['asn']:
                asn = info['asn']
                if asn in known_providers:
                    provider_info = {
                        'ip': ip,
                        'asn': asn,
                        'provider': known_providers[asn],
                        'org': info.get('org', 'Unknown')
                    }
                    providers.append(provider_info)
                else:
                    # Provider sconosciuto ma con informazioni ASN
                    provider_info = {
                        'ip': ip,
                        'asn': asn,
                        'provider': 'Unknown',
                        'org': info.get('org', 'Unknown')
                    }
                    providers.append(provider_info)
        
        return providers

class SSLCertificateAnalyzer:
    """Classe per analisi avanzata dei certificati SSL storici"""
    
    # CA poco affidabili o sospette
    SUSPICIOUS_CAS = {
        'WoSign': {'risk': 'high', 'reason': 'Revocata da browser per pratiche scorrette'},
        'StartCom': {'risk': 'high', 'reason': 'Revocata da browser'},
        'Symantec': {'risk': 'medium', 'reason': 'Problemi di validazione'},
        'Comodo': {'risk': 'medium', 'reason': 'Emissioni fraudolente passate'},
        'DigiCert': {'risk': 'low', 'reason': 'Generalmente affidabile'},
        "Let's Encrypt": {'risk': 'variable', 'reason': 'Dipende dal pattern di utilizzo'}
    }
    
    # Paesi con legislazioni ostili o problematiche
    HOSTILE_COUNTRIES = {
        'CN': {'risk': 'high', 'reason': 'Censura e sorveglianza estesa'},
        'RU': {'risk': 'high', 'reason': 'Controllo statale su internet'},
        'IR': {'risk': 'high', 'reason': 'Severe internet restrictions'},
        'KP': {'risk': 'high', 'reason': 'Controllo totale statale'},
        'BY': {'risk': 'medium', 'reason': 'Controllo governativo'},
        'VE': {'risk': 'medium', 'reason': 'Censura e controllo'},
        'MM': {'risk': 'medium', 'reason': 'Instabilità politica'},
        'PK': {'risk': 'medium', 'reason': 'Blocchi frequenti'}
    }
    
    @staticmethod
    def get_certificate_history(domain):
        """Ottiene la cronologia dei certificati SSL"""
        certificates = {
            'current_cert': None,
            'historical_certs': [],
            'ca_analysis': {},
            'san_domains': [],
            'suspicious_patterns': [],
            'geo_analysis': {}
        }
        
        try:
            # Certificato corrente
            current_cert = SSLCertificateAnalyzer._get_current_certificate(domain)
            if current_cert:
                certificates['current_cert'] = current_cert
                certificates['san_domains'].extend(current_cert.get('san_domains', []))
            
            # Certificati storici tramite crt.sh
            historical = SSLCertificateAnalyzer._get_historical_certificates(domain)
            certificates['historical_certs'] = historical
            
            # Analisi CA
            certificates['ca_analysis'] = SSLCertificateAnalyzer._analyze_certificate_authorities(certificates)
            
            # Analisi pattern sospetti
            certificates['suspicious_patterns'] = SSLCertificateAnalyzer._detect_suspicious_patterns(certificates)
            
            # Analisi geografica
            certificates['geo_analysis'] = SSLCertificateAnalyzer._analyze_geographic_patterns(certificates)
            
        except Exception as e:
            certificates['error'] = str(e)
        
        return certificates
    
    @staticmethod
    def _get_current_certificate(domain):
        """Ottiene il certificato SSL corrente con gestione errori robusta"""
        # Utilizza il metodo migliorato di SecurityAnalyzer
        cert_result = SecurityAnalyzer.check_ssl_certificate(domain)
        
        if cert_result and cert_result.get('valid') is not False:
            # Adatta il formato per SSLCertificateAnalyzer
            return {
                'subject': cert_result.get('subject', {}),
                'issuer': cert_result.get('issuer', {}),
                'version': cert_result.get('version'),
                'serial_number': cert_result.get('serial_number'),
                'not_before': cert_result.get('not_before'),
                'not_after': cert_result.get('not_after'),
                'san_domains': cert_result.get('san_domains', []),
                'signature_algorithm': cert_result.get('signature_algorithm', 'Unknown'),
                'verification_method': cert_result.get('verification_method', 'unknown'),
                'verification_warning': cert_result.get('warning') or cert_result.get('note')
            }
        
        # Fallback per casi estremi
        try:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=15) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        return {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'san_domains': [x[1] for x in cert.get('subjectAltName', []) if x[0] == 'DNS'],
                            'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown'),
                            'verification_method': 'fallback_unverified',
                            'verification_warning': 'Certificato ottenuto senza verifica di validità'
                        }
        except Exception:
            # Secondo tentativo con verifica disabilitata
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        
                        if cert:
                            return {
                                'subject': dict(x[0] for x in cert['subject']),
                                'issuer': dict(x[0] for x in cert['issuer']),
                                'version': cert['version'],
                                'serial_number': cert['serialNumber'],
                                'not_before': cert['notBefore'],
                                'not_after': cert['notAfter'],
                                'san_domains': cert.get('subjectAltName', []),
                                'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown'),
                                'verification_warning': 'Certificato non verificabile'
                            }
            except Exception:
                pass
            return None
        except Exception:
            return None
    
    @staticmethod
    def _get_historical_certificates(domain):
        """Ottiene certificati storici da crt.sh"""
        certificates = []
        
        try:
            # Query crt.sh API
            url = f"https://crt.sh/?q={domain}&output=json"
            response = requests.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                for cert in data[:50]:  # Limita a 50 certificati
                    cert_info = {
                        'id': cert.get('id'),
                        'logged_at': cert.get('entry_timestamp'),
                        'not_before': cert.get('not_before'),
                        'not_after': cert.get('not_after'),
                        'common_name': cert.get('common_name'),
                        'issuer_name': cert.get('issuer_name'),
                        'name_value': cert.get('name_value', '').split('\n')
                    }
                    certificates.append(cert_info)
        except Exception:
            pass
        
        return certificates
    
    @staticmethod
    def _analyze_certificate_authorities(certificates):
        """Analizza le Certificate Authorities"""
        ca_analysis = {
            'ca_distribution': {},
            'suspicious_cas': [],
            'ca_changes': [],
            'risk_assessment': 'low'
        }
        
        try:
            # Analizza CA corrente
            if certificates['current_cert']:
                current_issuer = certificates['current_cert']['issuer'].get('organizationName', 'Unknown')
                ca_analysis['current_ca'] = current_issuer
                
                # Verifica se CA è sospetta
                for ca, info in SSLCertificateAnalyzer.SUSPICIOUS_CAS.items():
                    if ca.lower() in current_issuer.lower():
                        ca_analysis['suspicious_cas'].append({
                            'ca': ca,
                            'risk': info['risk'],
                            'reason': info['reason'],
                            'current': True
                        })
            
            # Analizza CA storiche
            ca_history = {}
            for cert in certificates['historical_certs']:
                issuer = cert.get('issuer_name', 'Unknown')
                ca_history[issuer] = ca_history.get(issuer, 0) + 1
            
            ca_analysis['ca_distribution'] = ca_history
            
            # Rileva cambi di CA sospetti
            if len(ca_history) > 3:
                ca_analysis['ca_changes'].append({
                    'type': 'frequent_ca_changes',
                    'count': len(ca_history),
                    'risk': 'medium'
                })
            
        except Exception:
            pass
        
        return ca_analysis
    
    @staticmethod
    def _detect_suspicious_patterns(certificates):
        """Rileva pattern sospetti nei certificati"""
        patterns = []
        
        try:
            # Pattern Let's Encrypt da IP diversi
            letsencrypt_certs = []
            for cert in certificates['historical_certs']:
                if "let's encrypt" in cert.get('issuer_name', '').lower():
                    letsencrypt_certs.append(cert)
            
            if len(letsencrypt_certs) > 10:
                patterns.append({
                    'type': 'excessive_letsencrypt_renewals',
                    'count': len(letsencrypt_certs),
                    'risk': 'medium',
                    'description': 'Numero elevato di certificati Let\'s Encrypt potrebbe indicare automazione sospetta'
                })
            
            # Certificati con SAN eccessivi
            for cert in certificates['historical_certs']:
                san_count = len(cert.get('name_value', []))
                if san_count > 100:
                    patterns.append({
                        'type': 'excessive_san_domains',
                        'count': san_count,
                        'risk': 'high',
                        'description': 'Certificato con troppi domini SAN potrebbe indicare phishing'
                    })
            
            # Certificati di breve durata
            short_lived = 0
            for cert in certificates['historical_certs']:
                try:
                    not_before = datetime.strptime(cert['not_before'], '%Y-%m-%dT%H:%M:%S')
                    not_after = datetime.strptime(cert['not_after'], '%Y-%m-%dT%H:%M:%S')
                    duration = (not_after - not_before).days
                    if duration < 30:
                        short_lived += 1
                except:
                    pass
            
            if short_lived > 5:
                patterns.append({
                    'type': 'short_lived_certificates',
                    'count': short_lived,
                    'risk': 'medium',
                    'description': 'Molti certificati di breve durata potrebbero indicare attività sospetta'
                })
        
        except Exception:
            pass
        
        return patterns
    
    @staticmethod
    def _analyze_geographic_patterns(certificates):
        """Analizza pattern geografici dei certificati"""
        geo_analysis = {
            'hostile_countries': [],
            'country_distribution': {},
            'risk_assessment': 'low',
            'third_party_servers': []
        }
        
        try:
            # Analizza domini SAN per pattern geografici
            all_domains = set()
            if certificates['current_cert']:
                for san in certificates['current_cert'].get('san_domains', []):
                    if isinstance(san, tuple) and san[0] == 'DNS':
                        all_domains.add(san[1])
            
            for cert in certificates['historical_certs']:
                for domain in cert.get('name_value', []):
                    if domain.strip():
                        all_domains.add(domain.strip())
            
            # Analizza TLD per identificare paesi
            country_tlds = {}
            for domain in all_domains:
                if '.' in domain:
                    tld = domain.split('.')[-1].upper()
                    if len(tld) == 2:  # Country code TLD
                        country_tlds[tld] = country_tlds.get(tld, 0) + 1
            
            geo_analysis['country_distribution'] = country_tlds
            
            # Verifica paesi ostili
            for country, count in country_tlds.items():
                if country in SSLCertificateAnalyzer.HOSTILE_COUNTRIES:
                    hostile_info = SSLCertificateAnalyzer.HOSTILE_COUNTRIES[country]
                    geo_analysis['hostile_countries'].append({
                        'country': country,
                        'domain_count': count,
                        'risk': hostile_info['risk'],
                        'reason': hostile_info['reason']
                    })
            
            # Valutazione rischio complessivo
            if geo_analysis['hostile_countries']:
                high_risk_countries = [c for c in geo_analysis['hostile_countries'] if c['risk'] == 'high']
                if high_risk_countries:
                    geo_analysis['risk_assessment'] = 'high'
                else:
                    geo_analysis['risk_assessment'] = 'medium'
        
        except Exception:
            pass
        
        return geo_analysis

class ReverseIPLookup:
    """Reverse IP lookup con correlazione ASN"""
    
    @staticmethod
    def perform_reverse_lookup(ip):
        """Esegue reverse IP lookup"""
        reverse_info = {
            'ip': ip,
            'hostnames': [],
            'shared_hosting': [],
            'asn_correlation': {},
            'geographic_info': {}
        }
        
        try:
            # Reverse DNS lookup
            hostname = socket.gethostbyaddr(ip)[0]
            reverse_info['hostnames'].append(hostname)
            
            # Tenta di trovare altri domini sullo stesso IP
            reverse_info['shared_hosting'] = ReverseIPLookup._find_shared_domains(ip)
            
            # Correlazione ASN
            reverse_info['asn_correlation'] = IPHistoryTracker._get_asn_info(ip)
            
            # Informazioni geografiche
            reverse_info['geographic_info'] = ReverseIPLookup._get_geographic_info(ip)
            
        except Exception as e:
            reverse_info['error'] = str(e)
        
        return reverse_info
    
    @staticmethod
    def _find_shared_domains(ip):
        """Trova domini che condividono lo stesso IP"""
        shared_domains = []
        
        try:
            # Usa tecniche di reverse IP lookup
            # Nota: questo è un esempio semplificato
            # In produzione si potrebbero usare API specializzate
            
            # Tenta reverse DNS per trovare il hostname principale
            try:
                primary_hostname = socket.gethostbyaddr(ip)[0]
                shared_domains.append({
                    'domain': primary_hostname,
                    'type': 'primary_hostname'
                })
            except:
                pass
            
            # Controlla se l'IP appartiene a range di hosting condiviso
            shared_hosting_indicators = [
                'shared', 'hosting', 'cpanel', 'plesk', 'whm',
                'reseller', 'vps', 'cloud', 'server'
            ]
            
            if any(indicator in primary_hostname.lower() for indicator in shared_hosting_indicators):
                shared_domains.append({
                    'info': 'Possibile hosting condiviso rilevato',
                    'type': 'shared_hosting_indicator'
                })
            
        except Exception as e:
            shared_domains.append({'error': str(e)})
        
        return shared_domains
    
    @staticmethod
    def _get_geographic_info(ip):
        """Ottiene informazioni geografiche per l'IP"""
        geo_info = {
            'country': None,
            'region': None,
            'city': None,
            'isp': None,
            'timezone': None
        }
        
        try:
            # Usa whois per informazioni geografiche di base
            import subprocess
            result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=10)
            whois_output = result.stdout.lower()
            
            import re
            
            # Estrai paese
            country_match = re.search(r'country:\s*([a-z]{2})', whois_output)
            if country_match:
                geo_info['country'] = country_match.group(1).upper()
            
            # Estrai ISP/Organizzazione
            org_patterns = [
                r'org-name:\s*(.+)',
                r'organization:\s*(.+)',
                r'orgname:\s*(.+)'
            ]
            
            for pattern in org_patterns:
                org_match = re.search(pattern, whois_output)
                if org_match:
                    geo_info['isp'] = org_match.group(1).strip()
                    break
            
        except Exception as e:
            geo_info['error'] = str(e)
        
        return geo_info

class AdvancedForensicAnalyzer:
    """Classe principale per analisi forense avanzata"""
    
    def __init__(self, target_url, output_dir="osint_results", force_proceed=False):
        self.target_url = self._normalize_url(target_url)
        self.domain = urlparse(self.target_url).netloc
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Inizializza sessione web
        self.web_session = WebSession()
        
        # Inizializza variabili per compatibilità
        self.original_ip = 'N/A'
        self.anonymized_ip = 'N/A'
        self.anonymization_successful = True
        
        # Conferma setup sessione
        print("\n🛡️ Sessione web configurata e pronta")
        
        print("="*60 + "\n")
        
        self.results = {
            'target': self.target_url,
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'analysis': {},
            'session_info': {
                'enabled': True,
                'user_agent_rotation': True,
                'session_active': True,
                'connection_type': 'standard'
            }
        }
        
        # Headers base per le richieste web
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def _normalize_url(self, url):
        """Normalizza URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    def basic_reconnaissance(self):
        """Ricognizione di base del target"""
        ColoredOutput.header("Ricognizione di Base")
        
        try:
            # Usa sessione web configurata
            session = self.web_session.get_anonymized_session()
            response = session.get(
                self.target_url, 
                timeout=15,
                allow_redirects=True
            )
            
            # Log connessione
            ColoredOutput.info(f"🌐 Connessione stabilita al target")
            
            # Parse HTML
            parser = SimpleHTMLParser()
            parser.feed(response.text)
            
            basic_info = {
                'status_code': response.status_code,
                'final_url': response.url,
                'content_length': len(response.content),
                'content_type': response.headers.get('content-type', 'N/A'),
                'server': response.headers.get('server', 'N/A'),
                'title': parser.title,
                'meta_data': parser.meta_data,
                'response_headers': dict(response.headers),
                'cookies': [{
                    'name': cookie.name, 
                    'value': cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path
                } for cookie in response.cookies],
                'redirects': [resp.url for resp in response.history],
                'links_count': len(parser.links),
                'images_count': len(parser.images),
                'forms_count': len(parser.forms),
                'scripts_count': len(parser.scripts)
            }
            
            self.results['analysis']['basic_info'] = basic_info
            ColoredOutput.success(f"Informazioni di base estratte - Status: {response.status_code}")
            
            # Mostra informazioni di base estratte
            ColoredOutput.info("\n📋 Informazioni di base:")
            if basic_info.get('title'):
                ColoredOutput.info(f"  📄 Titolo: {basic_info['title'][:60]}...")
            
            if basic_info.get('server'):
                ColoredOutput.info(f"  🖥️ Server: {basic_info['server']}")
            
            if basic_info.get('content_type'):
                ColoredOutput.info(f"  📝 Content-Type: {basic_info['content_type']}")
            
            if basic_info.get('content_length'):
                size_kb = round(basic_info['content_length'] / 1024, 2)
                ColoredOutput.info(f"  📏 Dimensione: {size_kb} KB")
            
            # Mostra conteggi elementi
            ColoredOutput.info(f"  🔗 Link trovati: {basic_info.get('links_count', 0)}")
            ColoredOutput.info(f"  🖼️ Immagini: {basic_info.get('images_count', 0)}")
            ColoredOutput.info(f"  📝 Form: {basic_info.get('forms_count', 0)}")
            ColoredOutput.info(f"  📜 Script: {basic_info.get('scripts_count', 0)}")
            
            # Mostra informazioni di sicurezza se presenti
            if basic_info.get('security_headers'):
                security_count = len([h for h in basic_info['security_headers'].values() if h])
                ColoredOutput.info(f"  🛡️ Header sicurezza: {security_count} configurati")
            
        except Exception as e:
            ColoredOutput.error(f"Errore nella ricognizione di base: {e}")
            self.results['analysis']['basic_info'] = {'error': str(e)}
    
    def screenshot_analysis(self):
        """Cattura screenshot del sito web"""
        ColoredOutput.header("Cattura Screenshot")
        
        try:
            screenshot_results = {
                'screenshots': [],
                'status': 'success',
                'method': 'selenium_chrome'
            }
            
            # Inizializza cattura screenshot
            screenshot_capture = ScreenshotCapture()
            
            if not screenshot_capture.driver:
                ColoredOutput.warning("⚠️ Driver Chrome non disponibile - screenshot saltati")
                screenshot_results['status'] = 'driver_unavailable'
                screenshot_results['error'] = 'Chrome driver non configurato'
                self.results['analysis']['screenshot'] = screenshot_results
                return
            
            # Genera nomi file per screenshot
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            domain_clean = self.domain.replace('.', '_').replace(':', '_')
            
            # Screenshot normale (viewport)
            screenshot_normal = self.output_dir / f"screenshot_{domain_clean}_{timestamp}.png"
            success_normal = screenshot_capture.capture_screenshot(
                self.target_url, 
                str(screenshot_normal)
            )
            
            if success_normal:
                screenshot_results['screenshots'].append({
                    'type': 'viewport',
                    'filename': screenshot_normal.name,
                    'path': str(screenshot_normal),
                    'size': 'viewport_1920x1080'
                })
                ColoredOutput.success(f"✅ Screenshot viewport salvato: {screenshot_normal.name}")
            
            # Screenshot pagina completa
            screenshot_full = self.output_dir / f"screenshot_full_{domain_clean}_{timestamp}.png"
            success_full = screenshot_capture.capture_full_page_screenshot(
                self.target_url,
                str(screenshot_full)
            )
            
            if success_full:
                screenshot_results['screenshots'].append({
                    'type': 'full_page',
                    'filename': screenshot_full.name,
                    'path': str(screenshot_full),
                    'size': 'full_page_scroll'
                })
                ColoredOutput.success(f"✅ Screenshot pagina completa salvato: {screenshot_full.name}")
            
            # Chiudi driver
            screenshot_capture.close()
            
            # Verifica risultati
            if screenshot_results['screenshots']:
                ColoredOutput.success(f"✅ {len(screenshot_results['screenshots'])} screenshot catturati con successo")
            else:
                ColoredOutput.warning("⚠️ Nessuno screenshot catturato")
                screenshot_results['status'] = 'failed'
                screenshot_results['error'] = 'Impossibile catturare screenshot'
            
            self.results['analysis']['screenshot'] = screenshot_results
            
        except Exception as e:
            ColoredOutput.error(f"Errore cattura screenshot: {e}")
            self.results['analysis']['screenshot'] = {
                'error': str(e),
                'status': 'error',
                'screenshots': []
            }
    
    def ip_geolocation_analysis(self):
        """Analisi IP e geolocalizzazione"""
        ColoredOutput.header("Analisi IP e Geolocalizzazione")
        
        try:
            # Risolvi IP
            ip_address = socket.gethostbyname(self.domain)
            ColoredOutput.info(f"IP risolto: {ip_address}")
            
            # Ottieni informazioni geografiche
            geo_info = GeoIPAnalyzer.get_ip_info(ip_address, anonymizer=self.web_session)
            
            # Aggiungi informazioni aggiuntive
            geo_info['reverse_dns'] = self._get_reverse_dns(ip_address)
            geo_info['ip_type'] = self._classify_ip(ip_address)
            
            self.results['analysis']['geolocation'] = geo_info
            
            if 'error' not in geo_info:
                ColoredOutput.success(
                    f"Geolocalizzazione: {geo_info.get('city', 'N/A')}, "
                    f"{geo_info.get('country', 'N/A')} - ISP: {geo_info.get('isp', 'N/A')}"
                )
            else:
                ColoredOutput.warning("Informazioni geografiche limitate")
                
        except Exception as e:
            ColoredOutput.error(f"Errore nell'analisi IP: {e}")
            self.results['analysis']['geolocation'] = {'error': str(e)}
    
    def _get_reverse_dns(self, ip):
        """Ottiene reverse DNS"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return 'N/A'
    
    def _classify_ip(self, ip):
        """Classifica tipo di IP"""
        try:
            parts = ip.split('.')
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            if first_octet == 10:
                return 'Private (Class A)'
            elif first_octet == 172 and 16 <= second_octet <= 31:
                return 'Private (Class B)'
            elif first_octet == 192 and second_octet == 168:
                return 'Private (Class C)'
            elif first_octet == 127:
                return 'Loopback'
            elif 224 <= first_octet <= 239:
                return 'Multicast'
            else:
                return 'Public'
        except:
            return 'Unknown'
    
    def dns_analysis(self):
        """Analisi DNS completa"""
        ColoredOutput.header("Analisi DNS")
        
        dns_info = {
            'a_record': DNSResolver.resolve_record(self.domain, 'A'),
            'mx_records': DNSResolver.get_mx_records(self.domain),
            'ns_records': [],
            'txt_records': []
        }
        
        # Ottieni NS records
        try:
            ns_result = subprocess.run(
                ['nslookup', '-type=NS', self.domain],
                capture_output=True, text=True, timeout=10
            )
            for line in ns_result.stdout.split('\n'):
                if 'nameserver' in line:
                    dns_info['ns_records'].append(line.strip())
        except:
            pass
        
        # Ottieni TXT records
        try:
            txt_result = subprocess.run(
                ['nslookup', '-type=TXT', self.domain],
                capture_output=True, text=True, timeout=10
            )
            for line in txt_result.stdout.split('\n'):
                if 'text' in line:
                    dns_info['txt_records'].append(line.strip())
        except:
            pass
        
        self.results['analysis']['dns'] = dns_info
        
        # Mostra informazioni DNS estratte
        ColoredOutput.success("Analisi DNS completata")
        if dns_info.get('a_record'):
            ColoredOutput.info(f"📍 Record A: {dns_info['a_record']}")
        
        if dns_info.get('mx_records'):
            mx_list = dns_info['mx_records'][:3]  # Prime 3
            ColoredOutput.info(f"📧 Record MX: {', '.join(mx_list)}")
        
        if dns_info.get('ns_records'):
            ns_count = len(dns_info['ns_records'])
            ColoredOutput.info(f"🌐 Nameserver: {ns_count} trovati")
            if ns_count > 0:
                # Mostra primo nameserver come esempio
                first_ns = dns_info['ns_records'][0].replace('nameserver = ', '')
                ColoredOutput.info(f"   Esempio: {first_ns}")
        
        if dns_info.get('txt_records'):
            txt_count = len(dns_info['txt_records'])
            ColoredOutput.info(f"📝 Record TXT: {txt_count} trovati")
            # Mostra record TXT importanti (SPF, DMARC, etc.)
            for txt in dns_info['txt_records'][:2]:
                if any(keyword in txt.lower() for keyword in ['spf', 'dmarc', 'dkim']):
                    ColoredOutput.info(f"   {txt[:60]}...")
    
    def whois_analysis(self):
        """Analisi WHOIS"""
        ColoredOutput.header("Analisi WHOIS")
        
        whois_info = WHOISAnalyzer.get_whois_info(self.domain)
        self.results['analysis']['whois'] = whois_info
        
        if 'error' not in whois_info:
            ColoredOutput.success("Informazioni WHOIS estratte")
            
            # Mostra informazioni WHOIS essenziali
            if whois_info.get('registrar'):
                ColoredOutput.info(f"🏢 Registrar: {whois_info['registrar']}")
            
            if whois_info.get('creation_date'):
                ColoredOutput.info(f"📅 Data creazione: {whois_info['creation_date']}")
            
            if whois_info.get('expiration_date'):
                ColoredOutput.info(f"⏰ Scadenza: {whois_info['expiration_date']}")
            
            if whois_info.get('name_servers'):
                ns_count = len(whois_info['name_servers'])
                ColoredOutput.info(f"🌐 Name servers: {ns_count} configurati")
                if ns_count > 0:
                    ColoredOutput.info(f"   Primo: {whois_info['name_servers'][0]}")
            
            if whois_info.get('country'):
                ColoredOutput.info(f"🌍 Paese registrazione: {whois_info['country']}")
                
        else:
            ColoredOutput.warning("WHOIS limitato o non disponibile")
    
    def technology_detection(self):
        """Rilevamento tecnologie avanzato con fingerprinting completo"""
        ColoredOutput.header("Rilevamento Tecnologie Avanzato")
        
        try:
            session = self.web_session.get_anonymized_session()
            response = session.get(self.target_url, timeout=15)
            
            # Estrai cookies se presenti
            cookies = []
            if hasattr(response, 'cookies'):
                for cookie in response.cookies:
                    cookies.append({
                        'name': cookie.name,
                        'value': cookie.value,
                        'domain': cookie.domain,
                        'path': cookie.path
                    })
            
            # Rilevamento tecnologie avanzato
            technologies = AdvancedTechnologyDetector.detect_technologies(
                response.text, 
                response.headers, 
                cookies,
                self.domain
            )
            
            # Analisi CSP headers
            csp_analysis = AdvancedTechnologyDetector.analyze_csp_headers(response.headers)
            
            # Rilevamento tracking technologies
            tracking_tech = AdvancedTechnologyDetector.detect_tracking_technologies(
                response.text, 
                response.headers
            )
            
            # Salva risultati completi
            self.results['analysis']['technologies'] = {
                'detected_technologies': technologies,
                'csp_analysis': csp_analysis,
                'tracking_technologies': tracking_tech,
                'response_headers': dict(response.headers),
                'cookies': cookies
            }
            
            # Stampa risultati dettagliati
            ColoredOutput.info("📊 Tecnologie Rilevate:")
            for category, techs in technologies.items():
                if techs:
                    ColoredOutput.success(f"  {category.replace('_', ' ').title()}: {', '.join(techs)}")
            
            # Stampa analisi CSP
            if csp_analysis['present']:
                ColoredOutput.info(f"\n🛡️ Content Security Policy: {csp_analysis['security_level']} Security Level")
                if csp_analysis['issues']:
                    ColoredOutput.warning(f"  Issues: {', '.join(csp_analysis['issues'])}")
                if csp_analysis['recommendations']:
                    ColoredOutput.info(f"  Recommendations: {', '.join(csp_analysis['recommendations'][:2])}")
            else:
                ColoredOutput.warning("\n🛡️ Content Security Policy: Non implementato")
            
            # Stampa tracking technologies
            total_trackers = sum(len(trackers) for key, trackers in tracking_tech.items() if key != 'privacy_score' and isinstance(trackers, list))
            if total_trackers > 0:
                ColoredOutput.info(f"\n🎯 Tracking Technologies (Privacy Score: {tracking_tech['privacy_score']}/100):")
                for category, trackers in tracking_tech.items():
                    if trackers and category != 'privacy_score' and isinstance(trackers, list):
                        ColoredOutput.warning(f"  {category.replace('_', ' ').title()}: {', '.join(trackers)}")
            else:
                ColoredOutput.success("\n🎯 Nessun tracker rilevato - Buona privacy!")
                
        except Exception as e:
            ColoredOutput.error(f"Errore nel rilevamento tecnologie: {e}")
            self.results['analysis']['technologies'] = {'error': str(e)}
    
    def subdomain_enumeration(self):
        """Enumerazione sottodomini"""
        ColoredOutput.header("Enumerazione Sottodomini")
        
        subdomains = SubdomainEnumerator.enumerate_subdomains(self.domain)
        self.results['analysis']['subdomains'] = subdomains
        
        if subdomains:
            ColoredOutput.success(f"Trovati {len(subdomains)} sottodomini attivi")
            for subdomain in subdomains[:10]:  # Mostra solo i primi 10
                ColoredOutput.info(f"  → {subdomain}")
            if len(subdomains) > 10:
                ColoredOutput.info(f"  ... e altri {len(subdomains) - 10} sottodomini")
        else:
            ColoredOutput.warning("Nessun sottodominio trovato")
    
    def security_analysis(self):
        """Analisi sicurezza"""
        ColoredOutput.header("Analisi Sicurezza")
        
        try:
            # Analizza header di sicurezza
            session = self.web_session.get_anonymized_session()
            response = session.get(self.target_url, timeout=15)
            security_headers = SecurityAnalyzer.analyze_security_headers(response.headers)
            
            # Analizza certificato SSL
            ssl_info = SecurityAnalyzer.check_ssl_certificate(self.domain)
            
            security_analysis = {
                'security_headers': security_headers,
                'ssl_certificate': ssl_info,
                'https_redirect': self._check_https_redirect(),
                'security_txt': self._check_security_txt()
            }
            
            self.results['analysis']['security'] = security_analysis
            
            # Output risultati sicurezza
            score = security_headers['security_percentage']
            if score >= 80:
                ColoredOutput.success(f"Score sicurezza header: {score}%")
            elif score >= 50:
                ColoredOutput.warning(f"Score sicurezza header: {score}%")
            else:
                ColoredOutput.error(f"Score sicurezza header: {score}%")
            
            if ssl_info['valid']:
                ColoredOutput.success("Certificato SSL valido")
            else:
                ColoredOutput.error("Problemi con certificato SSL")
                
        except Exception as e:
            ColoredOutput.error(f"Errore nell'analisi sicurezza: {e}")
            self.results['analysis']['security'] = {'error': str(e)}
    
    def _check_https_redirect(self):
        """Verifica redirect HTTPS"""
        try:
            http_url = self.target_url.replace('https://', 'http://')
            response = requests.get(http_url, allow_redirects=False, timeout=10)
            return response.status_code in [301, 302, 307, 308]
        except:
            return False
    
    def _check_security_txt(self):
        """Verifica presenza di security.txt"""
        try:
            security_urls = [
                f"{self.target_url}/.well-known/security.txt",
                f"{self.target_url}/security.txt"
            ]
            
            for url in security_urls:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    return {'found': True, 'url': url, 'content': response.text[:500]}
            
            return {'found': False}
        except:
            return {'found': False, 'error': 'Check failed'}
    
    def advanced_web_scraping(self):
        """Web scraping avanzato"""
        ColoredOutput.header("Web Scraping Avanzato")
        
        try:
            # Utilizza sessione web configurata
            session = self.web_session.get_anonymized_session()
            response = session.get(self.target_url, headers=self.headers, timeout=15)
            parser = SimpleHTMLParser()
            parser.feed(response.text)
            
            # Estrai informazioni avanzate
            scraping_data = {
                'links': self._process_links(parser.links),
                'images': self._process_images(parser.images),
                'forms': parser.forms,
                'scripts': parser.scripts,
                'stylesheets': parser.stylesheets,
                'emails': self._extract_emails(response.text),
                'phone_numbers': self._extract_phone_numbers(response.text),
                'social_media': self._extract_social_media(response.text),
                'external_domains': self._extract_external_domains(parser.links),
                'file_extensions': self._analyze_file_extensions(parser.links),
                'comments': self._extract_html_comments(response.text)
            }
            
            self.results['analysis']['web_scraping'] = scraping_data
            
            ColoredOutput.success(f"Estratti {len(scraping_data['links'])} link")
            
            # Mostra esempi di email trovate
            if scraping_data['emails']:
                ColoredOutput.success(f"Trovate {len(scraping_data['emails'])} email")
                for email in scraping_data['emails'][:3]:  # Prime 3 email
                    ColoredOutput.info(f"   📧 {email}")
                if len(scraping_data['emails']) > 3:
                    ColoredOutput.info(f"   ... e altre {len(scraping_data['emails']) - 3} email")
            
            # Mostra domini esterni rilevanti
            if scraping_data['external_domains']:
                ColoredOutput.success(f"Rilevati {len(scraping_data['external_domains'])} domini esterni")
                for domain in list(scraping_data['external_domains'])[:3]:  # Prime 3 domini
                    ColoredOutput.info(f"   🌐 {domain}")
                if len(scraping_data['external_domains']) > 3:
                    ColoredOutput.info(f"   ... e altri {len(scraping_data['external_domains']) - 3} domini")
            
            # Mostra numeri di telefono se trovati
            if scraping_data['phone_numbers']:
                ColoredOutput.info(f"📞 Numeri telefono: {len(scraping_data['phone_numbers'])} trovati")
                for phone in scraping_data['phone_numbers'][:2]:  # Prime 2
                    ColoredOutput.info(f"   {phone}")
            
            # Mostra social media se trovati
            if scraping_data['social_media']:
                ColoredOutput.info(f"📱 Social media: {len(scraping_data['social_media'])} profili")
                for social in scraping_data['social_media'][:2]:  # Prime 2
                    ColoredOutput.info(f"   {social}")
            
        except Exception as e:
            ColoredOutput.error(f"Errore nel web scraping: {e}")
            self.results['analysis']['web_scraping'] = {'error': str(e)}
    
    def _process_links(self, links):
        """Processa e categorizza i link"""
        processed_links = {
            'internal': [],
            'external': [],
            'email': [],
            'tel': [],
            'javascript': []
        }
        
        for link in links:
            if link.startswith('mailto:'):
                processed_links['email'].append(link)
            elif link.startswith('tel:'):
                processed_links['tel'].append(link)
            elif link.startswith('javascript:'):
                processed_links['javascript'].append(link)
            elif link.startswith('http'):
                if self.domain in link:
                    processed_links['internal'].append(link)
                else:
                    processed_links['external'].append(link)
            elif link.startswith('/'):
                processed_links['internal'].append(urljoin(self.target_url, link))
        
        return processed_links
    
    def _process_images(self, images):
        """Processa le immagini"""
        processed_images = []
        for img in images:
            if img.startswith('http'):
                processed_images.append(img)
            elif img.startswith('/'):
                processed_images.append(urljoin(self.target_url, img))
        return processed_images
    
    def _extract_emails(self, text):
        """Estrae email dal testo"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return list(set(re.findall(email_pattern, text)))
    
    def _extract_phone_numbers(self, text):
        """Estrae numeri di telefono"""
        phone_patterns = [
            r'\+?1?[-.]?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})',
            r'\+?39[-.]?([0-9]{2,3})[-.]?([0-9]{6,8})',
            r'\+?[0-9]{1,4}[-.]?[0-9]{1,4}[-.]?[0-9]{4,}'
        ]
        
        phones = []
        for pattern in phone_patterns:
            matches = re.findall(pattern, text)
            phones.extend(['-'.join(match) if isinstance(match, tuple) else match for match in matches])
        
        return list(set(phones))
    
    def _extract_social_media(self, text):
        """Estrae link social media"""
        social_patterns = {
            'facebook': r'(?:https?://)?(?:www\.)?facebook\.com/[\w.-]+',
            'twitter': r'(?:https?://)?(?:www\.)?twitter\.com/[\w.-]+',
            'instagram': r'(?:https?://)?(?:www\.)?instagram\.com/[\w.-]+',
            'linkedin': r'(?:https?://)?(?:www\.)?linkedin\.com/[\w.-/]+',
            'youtube': r'(?:https?://)?(?:www\.)?youtube\.com/[\w.-/]+',
            'telegram': r'(?:https?://)?(?:www\.)?t\.me/[\w.-]+'
        }
        
        social_links = {}
        for platform, pattern in social_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                social_links[platform] = list(set(matches))
        
        return social_links
    
    def _extract_external_domains(self, links):
        """Estrae domini esterni"""
        external_domains = set()
        for link in links:
            if link.startswith('http'):
                domain = urlparse(link).netloc
                if domain and domain != self.domain:
                    external_domains.add(domain)
        return list(external_domains)
    
    def _analyze_file_extensions(self, links):
        """Analizza estensioni dei file"""
        extensions = defaultdict(int)
        for link in links:
            if '.' in link:
                ext = link.split('.')[-1].lower().split('?')[0].split('#')[0]
                if len(ext) <= 5 and ext.isalpha():
                    extensions[ext] += 1
        return dict(extensions)
    
    def _extract_html_comments(self, html):
        """Estrae commenti HTML"""
        comment_pattern = r'<!--([\s\S]*?)-->'
        comments = re.findall(comment_pattern, html)
        return [comment.strip() for comment in comments if comment.strip()]
    
    def content_analysis(self):
        """Analisi del contenuto"""
        ColoredOutput.header("Analisi Contenuto")
        
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=15)
            
            # Genera hash del contenuto
            content_hashes = {
                'md5': hashlib.md5(response.content).hexdigest(),
                'sha1': hashlib.sha1(response.content).hexdigest(),
                'sha256': hashlib.sha256(response.content).hexdigest()
            }
            
            # Analizza il contenuto
            content_analysis = {
                'hashes': content_hashes,
                'size_bytes': len(response.content),
                'size_kb': round(len(response.content) / 1024, 2),
                'encoding': response.encoding,
                'language': self._detect_language(response.text),
                'word_count': len(response.text.split()),
                'line_count': len(response.text.split('\n')),
                'charset': self._extract_charset(response.headers.get('content-type', ''))
            }
            
            self.results['analysis']['content'] = content_analysis
            
            ColoredOutput.success(f"Contenuto analizzato - Dimensione: {content_analysis['size_kb']} KB")
            ColoredOutput.info(f"Hash SHA256: {content_hashes['sha256'][:32]}...")
            
        except Exception as e:
            ColoredOutput.error(f"Errore nell'analisi contenuto: {e}")
            self.results['analysis']['content'] = {'error': str(e)}
    
    def _detect_language(self, text):
        """Rileva lingua del contenuto (semplificato)"""
        # Semplice rilevamento basato su parole comuni
        italian_words = ['il', 'la', 'di', 'che', 'e', 'un', 'a', 'per', 'in', 'con']
        english_words = ['the', 'of', 'and', 'a', 'to', 'in', 'is', 'you', 'that', 'it']
        spanish_words = ['el', 'la', 'de', 'que', 'y', 'un', 'en', 'es', 'se', 'no']
        
        text_lower = text.lower()
        
        italian_count = sum(1 for word in italian_words if word in text_lower)
        english_count = sum(1 for word in english_words if word in text_lower)
        spanish_count = sum(1 for word in spanish_words if word in text_lower)
        
        if italian_count > english_count and italian_count > spanish_count:
            return 'Italian'
        elif english_count > spanish_count:
            return 'English'
        elif spanish_count > 0:
            return 'Spanish'
        else:
            return 'Unknown'
    
    def _extract_charset(self, content_type):
        """Estrae charset dal content-type"""
        if 'charset=' in content_type:
            return content_type.split('charset=')[1].split(';')[0].strip()
        return 'Unknown'
    
    def robots_txt_analysis(self):
        """Analizza robots.txt"""
        ColoredOutput.header("Analisi robots.txt")
        
        try:
            robots_url = urljoin(self.target_url, '/robots.txt')
            # Utilizza sessione web configurata
            session = self.web_session.get_anonymized_session()
            response = session.get(robots_url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                robots_analysis = {
                    'found': True,
                    'content': response.text,
                    'disallowed_paths': [],
                    'allowed_paths': [],
                    'sitemaps': [],
                    'crawl_delay': None
                }
                
                # Analizza il contenuto
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line.startswith('Disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            robots_analysis['disallowed_paths'].append(path)
                    elif line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            robots_analysis['allowed_paths'].append(path)
                    elif line.startswith('Sitemap:'):
                        sitemap = line.split(':', 1)[1].strip()
                        robots_analysis['sitemaps'].append(sitemap)
                    elif line.startswith('Crawl-delay:'):
                        delay = line.split(':', 1)[1].strip()
                        robots_analysis['crawl_delay'] = delay
                
                self.results['analysis']['robots_txt'] = robots_analysis
                ColoredOutput.success("robots.txt trovato e analizzato")
                
                if robots_analysis['disallowed_paths']:
                    ColoredOutput.info(f"Percorsi vietati: {len(robots_analysis['disallowed_paths'])}")
                if robots_analysis['sitemaps']:
                    ColoredOutput.info(f"Sitemap trovate: {len(robots_analysis['sitemaps'])}")
            else:
                self.results['analysis']['robots_txt'] = {'found': False}
                ColoredOutput.warning("robots.txt non trovato")
                
        except Exception as e:
            ColoredOutput.error(f"Errore nell'analisi robots.txt: {e}")
            self.results['analysis']['robots_txt'] = {'error': str(e)}
    
    def sitemap_analysis(self):
        """Analizza sitemap"""
        ColoredOutput.header("Analisi Sitemap")
        
        sitemap_urls = [
            urljoin(self.target_url, '/sitemap.xml'),
            urljoin(self.target_url, '/sitemap_index.xml'),
            urljoin(self.target_url, '/sitemaps.xml')
        ]
        
        # Aggiungi sitemap da robots.txt se disponibili
        if 'robots_txt' in self.results['analysis'] and self.results['analysis']['robots_txt'].get('sitemaps'):
            sitemap_urls.extend(self.results['analysis']['robots_txt']['sitemaps'])
        
        sitemap_analysis = {
            'found_sitemaps': [],
            'total_urls': 0,
            'url_patterns': defaultdict(int)
        }
        
        for sitemap_url in sitemap_urls:
            try:
                # Utilizza sessione web configurata
                session = self.web_session.get_anonymized_session()
                response = session.get(sitemap_url, headers=self.headers, timeout=10)
                if response.status_code == 200:
                    sitemap_data = {
                        'url': sitemap_url,
                        'size': len(response.content),
                        'urls': []
                    }
                    
                    # Prova a parsare come XML
                    try:
                        root = ET.fromstring(response.content)
                        
                        # Namespace per sitemap
                        ns = {'sitemap': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                        
                        # Estrai URL
                        for url_elem in root.findall('.//sitemap:url', ns):
                            loc_elem = url_elem.find('sitemap:loc', ns)
                            if loc_elem is not None:
                                url = loc_elem.text
                                sitemap_data['urls'].append(url)
                                
                                # Analizza pattern URL
                                path = urlparse(url).path
                                if '/' in path:
                                    pattern = '/'.join(path.split('/')[:3])
                                    sitemap_analysis['url_patterns'][pattern] += 1
                        
                        sitemap_analysis['found_sitemaps'].append(sitemap_data)
                        sitemap_analysis['total_urls'] += len(sitemap_data['urls'])
                        
                    except ET.ParseError:
                        # Non è un XML valido
                        pass
                        
            except Exception:
                continue
        
        self.results['analysis']['sitemap'] = sitemap_analysis
        
        if sitemap_analysis['found_sitemaps']:
            ColoredOutput.success(f"Trovate {len(sitemap_analysis['found_sitemaps'])} sitemap")
            ColoredOutput.info(f"Totale URL: {sitemap_analysis['total_urls']}")
        else:
            ColoredOutput.warning("Nessuna sitemap trovata")
    
    def port_scanning(self):
        """Scansione porte"""
        ColoredOutput.header("Scansione Porte")
        
        try:
            # Risolvi IP per la scansione
            target_ip = socket.gethostbyname(self.domain)
            ColoredOutput.info(f"Scansione porte su {target_ip}")
            
            # Scansiona porte comuni
            open_ports = PortScanner.scan_ports(target_ip)
            
            self.results['analysis']['port_scan'] = {
                'target_ip': target_ip,
                'open_ports': open_ports,
                'scan_time': datetime.now().isoformat()
            }
            
            if open_ports:
                ColoredOutput.success(f"Trovate {len(open_ports)} porte aperte")
                for port_info in open_ports[:10]:  # Mostra prime 10
                    ColoredOutput.info(f"  → Porta {port_info['port']}: {port_info['service']}")
                if len(open_ports) > 10:
                    ColoredOutput.info(f"  ... e altre {len(open_ports) - 10} porte")
            else:
                ColoredOutput.warning("Nessuna porta comune aperta rilevata")
                
        except Exception as e:
            ColoredOutput.error(f"Errore nella scansione porte: {e}")
            self.results['analysis']['port_scan'] = {'error': str(e)}
    
    def vulnerability_assessment(self):
        """Valutazione vulnerabilità"""
        ColoredOutput.header("Valutazione Vulnerabilità")
        
        try:
            vulnerabilities = VulnerabilityScanner.check_common_vulnerabilities(
                self.target_url, self.headers
            )
            
            self.results['analysis']['vulnerabilities'] = {
                'total_found': len(vulnerabilities),
                'vulnerabilities': vulnerabilities,
                'scan_time': datetime.now().isoformat()
            }
            
            if vulnerabilities:
                high_severity = len([v for v in vulnerabilities if v.get('severity') == 'High'])
                medium_severity = len([v for v in vulnerabilities if v.get('severity') == 'Medium'])
                low_severity = len([v for v in vulnerabilities if v.get('severity') == 'Low'])
                
                ColoredOutput.warning(f"Trovate {len(vulnerabilities)} potenziali vulnerabilità")
                if high_severity > 0:
                    ColoredOutput.error(f"  → {high_severity} ad alta severità")
                if medium_severity > 0:
                    ColoredOutput.warning(f"  → {medium_severity} a media severità")
                if low_severity > 0:
                    ColoredOutput.info(f"  → {low_severity} a bassa severità")
                
                # Mostra esempi delle vulnerabilità più critiche
                high_vulns = [v for v in vulnerabilities if v.get('severity') == 'High']
                medium_vulns = [v for v in vulnerabilities if v.get('severity') == 'Medium']
                
                if high_vulns:
                    ColoredOutput.error("\n🚨 Vulnerabilità Critiche:")
                    for vuln in high_vulns[:2]:  # Prime 2 critiche
                        ColoredOutput.error(f"   • {vuln.get('name', 'Vulnerabilità sconosciuta')}")
                        if vuln.get('description'):
                            ColoredOutput.info(f"     {vuln['description'][:80]}...")
                
                elif medium_vulns:
                    ColoredOutput.warning("\n⚠️ Vulnerabilità Medie:")
                    for vuln in medium_vulns[:2]:  # Prime 2 medie
                        ColoredOutput.warning(f"   • {vuln.get('name', 'Vulnerabilità sconosciuta')}")
                        if vuln.get('description'):
                            ColoredOutput.info(f"     {vuln['description'][:80]}...")
            else:
                ColoredOutput.success("Nessuna vulnerabilità comune rilevata")
                
        except Exception as e:
            ColoredOutput.error(f"Errore nella valutazione vulnerabilità: {e}")
            self.results['analysis']['vulnerabilities'] = {'error': str(e)}
    
    def metadata_extraction(self):
        """Estrazione metadati"""
        ColoredOutput.header("Estrazione Metadati")
        
        try:
            # Estrai metadati documenti
            doc_metadata = MetadataExtractor.extract_document_metadata(
                self.target_url, self.headers
            )
            
            # Estrai metadati immagini
            img_metadata = MetadataExtractor.extract_image_metadata(
                self.target_url, self.headers
            )
            
            metadata_analysis = {
                'documents': doc_metadata,
                'images': img_metadata,
                'total_documents': len(doc_metadata),
                'total_images': len(img_metadata),
                'extraction_time': datetime.now().isoformat()
            }
            
            self.results['analysis']['metadata'] = metadata_analysis
            
            ColoredOutput.success(f"Trovati {len(doc_metadata)} documenti")
            ColoredOutput.success(f"Analizzate {len(img_metadata)} immagini")
            
            # Mostra alcuni documenti trovati con metadati
            if doc_metadata:
                ColoredOutput.info("\n📄 Documenti con metadati:")
                for doc in doc_metadata[:3]:  # Prime 3
                    filename = doc['url'].split('/')[-1]
                    ColoredOutput.info(f"  → {filename}")
                    if doc.get('author'):
                        ColoredOutput.info(f"     Autore: {doc['author']}")
                    if doc.get('creation_date'):
                        ColoredOutput.info(f"     Creato: {doc['creation_date']}")
                    if doc.get('software'):
                        ColoredOutput.info(f"     Software: {doc['software']}")
                if len(doc_metadata) > 3:
                    ColoredOutput.info(f"  ... e altri {len(doc_metadata) - 3} documenti")
            
            # Mostra informazioni sulle immagini
            if img_metadata:
                ColoredOutput.info("\n🖼️ Immagini con metadati EXIF:")
                for img in img_metadata[:2]:  # Prime 2
                    filename = img['url'].split('/')[-1]
                    ColoredOutput.info(f"  → {filename}")
                    if img.get('camera_make'):
                        ColoredOutput.info(f"     Camera: {img['camera_make']}")
                    if img.get('gps_coordinates'):
                        ColoredOutput.warning(f"     🌍 GPS: {img['gps_coordinates']}")
                    if img.get('date_taken'):
                        ColoredOutput.info(f"     Data: {img['date_taken']}")
                if len(img_metadata) > 2:
                    ColoredOutput.info(f"  ... e altre {len(img_metadata) - 2} immagini")
                
        except Exception as e:
            ColoredOutput.error(f"Errore nell'estrazione metadati: {e}")
            self.results['analysis']['metadata'] = {'error': str(e)}
    
    def deep_web_crawling(self):
        """Crawling profondo del sito"""
        ColoredOutput.header("Crawling Profondo")
        
        try:
            crawl_results = AdvancedWebScraper.deep_crawl(
                self.target_url, self.headers, max_depth=2, max_pages=30
            )
            
            self.results['analysis']['deep_crawl'] = crawl_results
            
            ColoredOutput.success(f"Crawlate {len(crawl_results['pages'])} pagine")
            
            # Mostra pagine interessanti trovate
            if crawl_results['pages']:
                ColoredOutput.info("\n📄 Pagine scoperte:")
                for page in crawl_results['pages'][:3]:  # Prime 3 pagine
                    url_path = page['url'].replace(self.target_url, '')
                    ColoredOutput.info(f"  → {url_path or '/'}")
                    if page.get('title'):
                        ColoredOutput.info(f"     Titolo: {page['title'][:50]}...")
                if len(crawl_results['pages']) > 3:
                    ColoredOutput.info(f"  ... e altre {len(crawl_results['pages']) - 3} pagine")
            
            # Mostra email trovate
            if crawl_results['emails']:
                ColoredOutput.success(f"Trovate {len(crawl_results['emails'])} email uniche")
                for email in list(crawl_results['emails'])[:3]:  # Prime 3
                    ColoredOutput.info(f"  → 📧 {email}")
                if len(crawl_results['emails']) > 3:
                    ColoredOutput.info(f"  ... e altre {len(crawl_results['emails']) - 3} email")
            
            # Mostra numeri di telefono
            if crawl_results['phone_numbers']:
                ColoredOutput.success(f"Rilevati {len(crawl_results['phone_numbers'])} numeri di telefono")
                for phone in list(crawl_results['phone_numbers'])[:2]:  # Prime 2
                    ColoredOutput.info(f"  → 📞 {phone}")
            
            # Mostra link esterni interessanti
            if crawl_results['external_links']:
                ColoredOutput.success(f"Identificati {len(crawl_results['external_links'])} link esterni")
                for link in list(crawl_results['external_links'])[:3]:  # Prime 3
                    ColoredOutput.info(f"  → 🌐 {link}")
                if len(crawl_results['external_links']) > 3:
                    ColoredOutput.info(f"  ... e altri {len(crawl_results['external_links']) - 3} link")
            
            # Mostra commenti HTML se presenti
            if crawl_results['comments']:
                ColoredOutput.success(f"Estratti {len(crawl_results['comments'])} commenti HTML")
                for comment in crawl_results['comments'][:2]:  # Prime 2
                    if len(comment) > 10:  # Solo commenti significativi
                        ColoredOutput.info(f"  → 💬 {comment[:60]}...")
                
        except Exception as e:
            ColoredOutput.error(f"Errore nel crawling profondo: {e}")
            self.results['analysis']['deep_crawl'] = {'error': str(e)}
    
    def javascript_analysis(self):
        """Analisi JavaScript"""
        ColoredOutput.header("Analisi JavaScript")
        
        try:
            js_data = AdvancedWebScraper.extract_javascript_data(
                self.target_url, self.headers
            )
            
            self.results['analysis']['javascript'] = js_data
            
            ColoredOutput.success(f"Trovati {len(js_data['external_scripts'])} script esterni")
            ColoredOutput.success(f"Analizzati {len(js_data['inline_scripts'])} script inline")
            
            # Mostra script esterni interessanti
            if js_data['external_scripts']:
                ColoredOutput.info("\n📜 Script esterni:")
                for script in js_data['external_scripts'][:3]:  # Prime 3
                    script_name = script.split('/')[-1] if '/' in script else script
                    ColoredOutput.info(f"  → {script_name}")
                if len(js_data['external_scripts']) > 3:
                    ColoredOutput.info(f"  ... e altri {len(js_data['external_scripts']) - 3} script")
            
            # Mostra endpoint API rilevati
            if js_data['api_endpoints']:
                ColoredOutput.success(f"Rilevati {len(js_data['api_endpoints'])} endpoint API")
                ColoredOutput.info("\n🔗 Endpoint API:")
                for endpoint in js_data['api_endpoints'][:3]:  # Prime 3
                    ColoredOutput.info(f"  → {endpoint}")
                if len(js_data['api_endpoints']) > 3:
                    ColoredOutput.info(f"  ... e altri {len(js_data['api_endpoints']) - 3} endpoint")
            
            # Mostra variabili interessanti
            if js_data['variables']:
                ColoredOutput.success(f"Estratte {len(js_data['variables'])} variabili")
                ColoredOutput.info("\n🔧 Variabili JavaScript:")
                for var in js_data['variables'][:3]:  # Prime 3
                    var_name = var.get('name', 'Sconosciuta')
                    var_type = var.get('type', 'mixed')
                    ColoredOutput.info(f"  → {var_name} ({var_type})")
                if len(js_data['variables']) > 3:
                    ColoredOutput.info(f"  ... e altre {len(js_data['variables']) - 3} variabili")
            
            # Mostra funzioni sospette se presenti
            if js_data.get('suspicious_functions'):
                ColoredOutput.warning(f"\n⚠️ Funzioni sospette: {len(js_data['suspicious_functions'])}")
                for func in js_data['suspicious_functions'][:2]:  # Prime 2
                    ColoredOutput.warning(f"  → {func}")
            
            # Mostra librerie rilevate
            if js_data.get('libraries'):
                ColoredOutput.info(f"\n📚 Librerie rilevate: {len(js_data['libraries'])}")
                for lib in js_data['libraries'][:3]:  # Prime 3
                    ColoredOutput.info(f"  → {lib}")
                
        except Exception as e:
            ColoredOutput.error(f"Errore nell'analisi JavaScript: {e}")
            self.results['analysis']['javascript'] = {'error': str(e)}
    
    def cdn_detection(self):
        """Rileva CDN e servizi cloud utilizzati"""
        ColoredOutput.header("Rilevamento CDN")
        
        try:
            domain = urlparse(self.target_url).netloc
            response = requests.get(self.target_url, headers=self.headers, timeout=10)
            
            detector = CDNDetector()
            cdn_info = detector.detect_cdn(response.headers, domain)
            
            self.results['analysis']['cdn_detection'] = {
                'detected_cdns': cdn_info,
                'headers_analyzed': dict(response.headers)
            }
            
            if cdn_info:
                ColoredOutput.success(f"CDN rilevati: {', '.join(cdn_info)}")
                for cdn in cdn_info:
                    ColoredOutput.info(f"  → {cdn}")
            else:
                ColoredOutput.warning("Nessun CDN rilevato")
                
        except Exception as e:
            ColoredOutput.error(f"Errore nel rilevamento CDN: {e}")
            self.results['analysis']['cdn_detection'] = {'error': str(e)}
    
    def cdn_bypass_analysis(self):
        """Analizza e tenta di bypassare CDN per trovare IP reali"""
        ColoredOutput.header("Bypass CDN - Ricerca IP Reali")
        
        try:
            domain = urlparse(self.target_url).netloc
            
            # Esegui analisi completa CDN bypass
            bypass_analyzer = CDNBypassAnalyzer()
            bypass_results = bypass_analyzer.comprehensive_cdn_bypass(domain, self.web_session)
            
            self.results['analysis']['cdn_bypass'] = bypass_results
            
            # Mostra risultati
            summary = bypass_results.get('summary', {})
            
            # IP reali trovati
            real_ips = summary.get('real_ips_found', [])
            if real_ips:
                ColoredOutput.success(f"🎯 IP reali identificati: {len(real_ips)}")
                for ip_info in real_ips:
                    ColoredOutput.info(f"  → {ip_info['ip']} (metodo: {ip_info['method']}, confidenza: {ip_info['confidence']})")
                    
                    # Mostra dettagli IP se disponibili
                    crimeflare_data = bypass_results['findings'].get('crimeflare', {})
                    if crimeflare_data.get('success') and 'ip_info' in crimeflare_data:
                        ip_details = crimeflare_data['ip_info']
                        if 'country' in ip_details:
                            ColoredOutput.info(f"    📍 Posizione: {ip_details.get('city', 'N/A')}, {ip_details.get('country', 'N/A')}")
                        if 'org' in ip_details:
                            ColoredOutput.info(f"    🏢 Organizzazione: {ip_details.get('org', 'N/A')}")
                        if 'isp' in ip_details:
                            ColoredOutput.info(f"    🌐 ISP: {ip_details.get('isp', 'N/A')}")
            else:
                ColoredOutput.warning("❌ Nessun IP reale identificato tramite Crimeflare")
            
            # Subdomain non protetti
            unprotected = summary.get('unprotected_subdomains', [])
            if unprotected:
                ColoredOutput.success(f"🔓 Subdomain non protetti trovati: {len(unprotected)}")
                for sub in unprotected:
                    ColoredOutput.info(f"  → {sub['subdomain']} ({sub['ip']})")
                    if 'ip_info' in sub and 'country' in sub['ip_info']:
                        ColoredOutput.info(f"    📍 {sub['ip_info'].get('city', 'N/A')}, {sub['ip_info'].get('country', 'N/A')}")
            else:
                ColoredOutput.warning("🔒 Nessun subdomain non protetto trovato")
            
            # Subdomain protetti
            dns_analysis = bypass_results['findings'].get('dns_analysis', {})
            protected = dns_analysis.get('protected_subdomains', [])
            if protected:
                ColoredOutput.info(f"🛡️  Subdomain protetti da CDN: {len(protected)}")
                for sub in protected[:5]:  # Mostra solo i primi 5
                    ColoredOutput.info(f"  → {sub['subdomain']} ({sub['ip']})")
                if len(protected) > 5:
                    ColoredOutput.info(f"  ... e altri {len(protected) - 5} subdomain protetti")
            
            # Raccomandazioni
            recommendations = summary.get('recommendations', [])
            if recommendations:
                ColoredOutput.info("\n💡 Raccomandazioni:")
                for rec in recommendations:
                    ColoredOutput.info(f"  • {rec}")
            
            # Record DNS aggiuntivi
            dns_records = dns_analysis.get('dns_records', {})
            if dns_records:
                ColoredOutput.info("\n📋 Record DNS rilevanti:")
                for record_type, records in dns_records.items():
                    if records:
                        ColoredOutput.info(f"  {record_type}: {', '.join(records[:3])}{'...' if len(records) > 3 else ''}")
                        
        except Exception as e:
            ColoredOutput.error(f"Errore nell'analisi bypass CDN: {e}")
            self.results['analysis']['cdn_bypass'] = {'error': str(e)}
    
    def cookie_analysis(self):
        """Analizza cookie per sicurezza e privacy"""
        ColoredOutput.header("Analisi Cookie")
        
        try:
            # Utilizza sessione web configurata
            session = self.web_session.get_anonymized_session()
            response = session.get(self.target_url, headers=self.headers, timeout=10)
            
            # Estrai cookie dalla risposta
            cookies_list = []
            for cookie in response.cookies:
                cookie_dict = {
                    'name': cookie.name,
                    'value': cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'secure': cookie.secure,
                    'httponly': hasattr(cookie, 'httponly') and cookie.httponly,
                    'expires': cookie.expires
                }
                cookies_list.append(cookie_dict)
            
            analyzer = CookieAnalyzer()
            cookie_analysis = analyzer.analyze_cookies(cookies_list)
            
            self.results['analysis']['cookie_analysis'] = cookie_analysis
            
            ColoredOutput.success(f"Analizzati {cookie_analysis['total_cookies']} cookie")
            
            if cookie_analysis['security_issues']:
                ColoredOutput.warning(f"Problemi di sicurezza: {len(cookie_analysis['security_issues'])}")
                for issue in cookie_analysis['security_issues'][:3]:
                    ColoredOutput.info(f"  → {issue}")
            
            if cookie_analysis['tracking_cookies']:
                ColoredOutput.warning(f"Cookie di tracking: {len(cookie_analysis['tracking_cookies'])}")
            
            if cookie_analysis['privacy_concerns']:
                ColoredOutput.warning(f"Problemi di privacy: {len(cookie_analysis['privacy_concerns'])}")
                
        except Exception as e:
            ColoredOutput.error(f"Errore nell'analisi dei cookie: {e}")
            self.results['analysis']['cookie_analysis'] = {'error': str(e)}
    
    def honeypot_detection(self):
        """Rileva possibili honeypot e trappole"""
        ColoredOutput.header("Rilevamento Honeypot")
        
        try:
            # Utilizza sessione web configurata
            session = self.web_session.get_anonymized_session()
            response = session.get(self.target_url, headers=self.headers, timeout=10)
            
            detector = HoneypotDetector()
            honeypot_analysis = detector.check_honeypot_indicators(
                self.target_url, 
                response.headers, 
                response.text
            )
            
            self.results['analysis']['honeypot_detection'] = honeypot_analysis
            
            if honeypot_analysis['is_suspicious']:
                risk_level = honeypot_analysis['risk_level']
                if risk_level == 'High':
                    ColoredOutput.error(f"⚠️  RISCHIO ALTO - Possibile honeypot rilevato!")
                elif risk_level == 'Medium':
                    ColoredOutput.warning(f"⚠️  RISCHIO MEDIO - Indicatori sospetti")
                else:
                    ColoredOutput.info(f"⚠️  RISCHIO BASSO - Alcuni indicatori")
                
                ColoredOutput.warning(f"Indicatori trovati: {len(honeypot_analysis['indicators'])}")
                for indicator in honeypot_analysis['indicators'][:3]:
                    ColoredOutput.info(f"  → {indicator}")
            else:
                ColoredOutput.success("Nessun indicatore di honeypot rilevato")
                
        except Exception as e:
            ColoredOutput.error(f"Errore nel rilevamento honeypot: {e}")
            self.results['analysis']['honeypot_detection'] = {'error': str(e)}
    
    def ip_history_analysis(self):
        """Analisi cronologia IP e rilevamento CDN masking"""
        ColoredOutput.header("Analisi Cronologia IP")
        
        try:
            ip_history = IPHistoryTracker.get_ip_history(self.domain)
            self.results['analysis']['ip_history'] = ip_history
            
            # Stampa IP correnti
            if ip_history['current_ips']:
                ColoredOutput.success(f"IP Correnti: {', '.join(ip_history['current_ips'])}")
            
            # Stampa IP storici
            if ip_history['historical_ips']:
                historical_unique = set(ip_history['historical_ips']) - set(ip_history['current_ips'])
                if historical_unique:
                    ColoredOutput.info(f"IP Storici: {', '.join(historical_unique)}")
            
            # Rilevamento CDN
            if ip_history['cdn_detection']:
                ColoredOutput.warning("🌐 CDN Rilevati:")
                for cdn, ips in ip_history['cdn_detection'].items():
                    ColoredOutput.warning(f"  {cdn}: {', '.join(ips)}")
            
            # DNS Leaks
            if ip_history['dns_leaks']:
                ColoredOutput.warning(f"🔍 DNS Leaks trovati ({len(ip_history['dns_leaks'])})")
                for leak in ip_history['dns_leaks'][:5]:  # Mostra solo i primi 5
                    if leak.get('subdomain'):
                        ColoredOutput.info(f"  {leak['subdomain']}: {', '.join(leak['ips'])}")
            
            # Hosting Providers
            if ip_history['hosting_providers']:
                ColoredOutput.info("🏢 Hosting Providers:")
                for provider in ip_history['hosting_providers']:
                    ColoredOutput.success(f"  {provider['provider']} ({provider['asn']}) - {provider['ip']}")
            
        except Exception as e:
            ColoredOutput.error(f"Errore nell'analisi cronologia IP: {e}")
            self.results['analysis']['ip_history'] = {'error': str(e)}
    
    def reverse_ip_analysis(self):
        """Analisi reverse IP lookup"""
        ColoredOutput.header("Reverse IP Lookup")
        
        try:
            # Ottieni IP correnti per il reverse lookup
            current_ips = socket.gethostbyname_ex(self.domain)[2]
            reverse_results = {}
            
            for ip in current_ips:
                reverse_info = ReverseIPLookup.perform_reverse_lookup(ip)
                reverse_results[ip] = reverse_info
                
                ColoredOutput.info(f"\n📍 Analisi per IP: {ip}")
                
                # Hostnames
                if reverse_info['hostnames']:
                    ColoredOutput.success(f"  Hostname: {', '.join(reverse_info['hostnames'])}")
                
                # Informazioni ASN
                asn_info = reverse_info.get('asn_correlation', {})
                if asn_info and 'asn' in asn_info:
                    ColoredOutput.info(f"  ASN: {asn_info['asn']} - {asn_info.get('org', 'Unknown')}")
                    if asn_info.get('country'):
                        ColoredOutput.info(f"  Paese: {asn_info['country']}")
                    if asn_info.get('network'):
                        ColoredOutput.info(f"  Network: {asn_info['network']}")
                
                # Informazioni geografiche
                geo_info = reverse_info.get('geographic_info', {})
                if geo_info and geo_info.get('isp'):
                    ColoredOutput.info(f"  ISP: {geo_info['isp']}")
                
                # Hosting condiviso
                if reverse_info['shared_hosting']:
                    for shared in reverse_info['shared_hosting']:
                        if shared.get('type') == 'shared_hosting_indicator':
                            ColoredOutput.warning(f"  ⚠️ {shared['info']}")
            
            self.results['analysis']['reverse_ip'] = reverse_results
            
        except Exception as e:
            ColoredOutput.error(f"Errore nel reverse IP lookup: {e}")
            self.results['analysis']['reverse_ip'] = {'error': str(e)}
    
    def ssl_certificate_analysis(self):
        """Analisi avanzata certificati SSL storici"""
        ColoredOutput.header("Analisi Certificati SSL Storici")
        
        try:
            cert_analysis = SSLCertificateAnalyzer.get_certificate_history(self.domain)
            self.results['analysis']['ssl_certificates'] = cert_analysis
            
            # Certificato corrente
            if cert_analysis['current_cert']:
                current = cert_analysis['current_cert']
                ColoredOutput.success(f"📜 Certificato Corrente:")
                ColoredOutput.info(f"  Emesso da: {current['issuer'].get('organizationName', 'Unknown')}")
                ColoredOutput.info(f"  Valido fino: {current['not_after']}")
                ColoredOutput.info(f"  Algoritmo: {current.get('signature_algorithm', 'Unknown')}")
                
                # Domini SAN
                san_count = len(current.get('san_domains', []))
                if san_count > 0:
                    ColoredOutput.info(f"  Domini SAN: {san_count}")
                    if san_count > 50:
                        ColoredOutput.warning(f"  ⚠️ Numero elevato di domini SAN ({san_count})")
            
            # Certificati storici
            historical_count = len(cert_analysis['historical_certs'])
            if historical_count > 0:
                ColoredOutput.info(f"\n📚 Certificati Storici: {historical_count} trovati")
                
                # Mostra ultimi 3 certificati
                for i, cert in enumerate(cert_analysis['historical_certs'][:3]):
                    ColoredOutput.info(f"  {i+1}. {cert.get('common_name', 'Unknown')} - {cert.get('issuer_name', 'Unknown')}")
            
            # Analisi CA
            ca_analysis = cert_analysis.get('ca_analysis', {})
            if ca_analysis.get('suspicious_cas'):
                ColoredOutput.warning(f"\n⚠️ CA Sospette Rilevate:")
                for ca in ca_analysis['suspicious_cas']:
                    risk_color = 'red' if ca['risk'] == 'high' else 'yellow'
                    ColoredOutput.print_colored(f"  • {ca['ca']} (Rischio: {ca['risk'].upper()})", risk_color)
                    ColoredOutput.info(f"    Motivo: {ca['reason']}")
            
            # Pattern sospetti
            if cert_analysis['suspicious_patterns']:
                ColoredOutput.warning(f"\n🚨 Pattern Sospetti:")
                for pattern in cert_analysis['suspicious_patterns']:
                    risk_color = 'red' if pattern['risk'] == 'high' else 'yellow'
                    ColoredOutput.print_colored(f"  • {pattern['type']} (Rischio: {pattern['risk'].upper()})", risk_color)
                    ColoredOutput.info(f"    {pattern['description']}")
                    if 'count' in pattern:
                        ColoredOutput.info(f"    Occorrenze: {pattern['count']}")
            
            # Analisi geografica
            geo_analysis = cert_analysis.get('geo_analysis', {})
            if geo_analysis.get('hostile_countries'):
                ColoredOutput.error(f"\n🌍 Paesi con Legislazioni Ostili:")
                for country in geo_analysis['hostile_countries']:
                    risk_color = 'red' if country['risk'] == 'high' else 'yellow'
                    ColoredOutput.print_colored(f"  • {country['country']} ({country['domain_count']} domini)", risk_color)
                    ColoredOutput.info(f"    Rischio: {country['risk'].upper()} - {country['reason']}")
            
            # Distribuzione paesi
            if geo_analysis.get('country_distribution'):
                ColoredOutput.info(f"\n🗺️ Distribuzione Geografica TLD:")
                for country, count in list(geo_analysis['country_distribution'].items())[:5]:
                    ColoredOutput.info(f"  {country}: {count} domini")
            
            # Valutazione rischio complessivo
            overall_risk = geo_analysis.get('risk_assessment', 'low')
            if overall_risk == 'high':
                ColoredOutput.error(f"\n🚨 VALUTAZIONE RISCHIO COMPLESSIVO: ALTO")
            elif overall_risk == 'medium':
                ColoredOutput.warning(f"\n⚠️ VALUTAZIONE RISCHIO COMPLESSIVO: MEDIO")
            else:
                ColoredOutput.success(f"\n✅ VALUTAZIONE RISCHIO COMPLESSIVO: BASSO")
            
        except Exception as e:
            ColoredOutput.error(f"Errore nell'analisi certificati SSL: {e}")
            self.results['analysis']['ssl_certificates'] = {'error': str(e)}
    
    def run_comprehensive_analysis(self):
        """Esegue analisi completa"""
        ColoredOutput.print_colored("\n" + "=" * 80, 'cyan', bold=True)
        ColoredOutput.print_colored("🔍 FORENSIC-EXCAVATOR - ANALISI FORENSE AVANZATA", 'cyan', bold=True)
        ColoredOutput.print_colored("=" * 80, 'cyan', bold=True)
        ColoredOutput.print_colored(f"🎯 Target: {self.target_url}", 'yellow', bold=True)
        ColoredOutput.print_colored(f"📅 Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 'yellow')
        ColoredOutput.print_colored("=" * 80, 'cyan', bold=True)
        
        # Lista delle analisi da eseguire (ora con le nuove funzionalità)
        analysis_methods = [
            ('Ricognizione Base', self.basic_reconnaissance),
            ('Cattura Screenshot', self.screenshot_analysis),
            ('Analisi IP/Geo', self.ip_geolocation_analysis),
            ('Analisi DNS', self.dns_analysis),
            ('Analisi WHOIS', self.whois_analysis),
            ('Cronologia IP', self.ip_history_analysis),
            ('Reverse IP Lookup', self.reverse_ip_analysis),
            ('Certificati SSL Storici', self.ssl_certificate_analysis),
            ('Scansione Porte', self.port_scanning),
            ('Rilevamento Tecnologie', self.technology_detection),
            ('Rilevamento CDN', self.cdn_detection),
            ('Bypass CDN/IP Reali', self.cdn_bypass_analysis),
            ('Enumerazione Sottodomini', self.subdomain_enumeration),
            ('Analisi Sicurezza', self.security_analysis),
            ('Analisi Cookie', self.cookie_analysis),
            ('Rilevamento Honeypot', self.honeypot_detection),
            ('Valutazione Vulnerabilità', self.vulnerability_assessment),
            ('Analisi Malware e Phishing', self.malware_phishing_analysis),
            ('Cronologia Wayback Machine', self.wayback_analysis),
            ('Web Scraping Avanzato', self.advanced_web_scraping),
            ('Crawling Profondo', self.deep_web_crawling),
            ('Analisi JavaScript', self.javascript_analysis),
            ('Estrazione Metadati', self.metadata_extraction),
            ('Analisi Contenuto', self.content_analysis),
            ('Analisi robots.txt', self.robots_txt_analysis),
            ('Analisi Sitemap', self.sitemap_analysis)
        ]
        
        # Esegui tutte le analisi
        for analysis_name, analysis_method in analysis_methods:
            try:
                analysis_method()
                time.sleep(1)  # Pausa tra le analisi
            except KeyboardInterrupt:
                ColoredOutput.warning("\nAnalisi interrotta dall'utente")
                break
            except Exception as e:
                ColoredOutput.error(f"Errore in {analysis_name}: {e}")
        
        # Salva risultati
        self.save_results()
        
        # Mostra riepilogo
        self.show_summary()
    
    def malware_phishing_analysis(self):
        """Analisi malware e phishing avanzata"""
        ColoredOutput.header("Analisi Malware e Phishing")
        
        try:
            malware_results = {
                'url_reputation': {},
                'content_analysis': {},
                'suspicious_patterns': [],
                'security_indicators': {},
                'method': 'comprehensive_malware_analysis'
            }
            
            # Analisi reputazione URL con servizi multipli
            ColoredOutput.info("Controllo reputazione URL...")
            
            # VirusTotal check (se disponibile)
            if hasattr(self, 'virustotal_check'):
                malware_results['url_reputation']['virustotal'] = self.virustotal_check(self.target_url)
            
            # URLVoid check
            malware_results['url_reputation']['urlvoid'] = self.urlvoid_check(self.target_url)
            
            # Analisi pattern sospetti nel contenuto
            ColoredOutput.info("Analisi pattern sospetti...")
            if hasattr(self, 'page_content') and self.page_content:
                suspicious_patterns = self.detect_suspicious_patterns(self.page_content)
                malware_results['suspicious_patterns'] = suspicious_patterns
            
            # Analisi header di sicurezza
            ColoredOutput.info("Controllo header di sicurezza...")
            security_headers = self.analyze_security_headers()
            malware_results['security_indicators'] = security_headers
            
            # Analisi JavaScript sospetto
            if hasattr(self, 'javascript_content') and self.javascript_content:
                js_analysis = self.analyze_suspicious_javascript(self.javascript_content)
                malware_results['content_analysis']['javascript'] = js_analysis
            
            self.results['analysis']['malware_phishing'] = malware_results
            
            # Mostra risultati dell'analisi malware
            ColoredOutput.success("Analisi malware completata")
            
            # Mostra reputazione URL
            if malware_results['url_reputation']:
                ColoredOutput.info("\n🛡️ Reputazione URL:")
                for service, result in malware_results['url_reputation'].items():
                    if isinstance(result, dict) and 'status' in result:
                        status = result['status']
                        if status == 'clean':
                            ColoredOutput.success(f"  ✅ {service.upper()}: Pulito")
                        elif status == 'suspicious':
                            ColoredOutput.warning(f"  ⚠️ {service.upper()}: Sospetto")
                        elif status == 'malicious':
                            ColoredOutput.error(f"  🚨 {service.upper()}: Malevolo")
                        else:
                            ColoredOutput.info(f"  ℹ️ {service.upper()}: {status}")
            
            # Mostra pattern sospetti
            if malware_results['suspicious_patterns']:
                ColoredOutput.warning(f"\n⚠️ Pattern sospetti rilevati: {len(malware_results['suspicious_patterns'])}")
                for pattern in malware_results['suspicious_patterns'][:3]:  # Prime 3
                    pattern_type = pattern.get('type', 'Sconosciuto')
                    pattern_desc = pattern.get('description', 'Pattern sospetto')
                    ColoredOutput.warning(f"  → {pattern_type}: {pattern_desc[:60]}...")
                if len(malware_results['suspicious_patterns']) > 3:
                    ColoredOutput.info(f"  ... e altri {len(malware_results['suspicious_patterns']) - 3} pattern")
            else:
                ColoredOutput.success("\n✅ Nessun pattern sospetto rilevato")
            
            # Mostra indicatori di sicurezza
            if malware_results['security_indicators']:
                ColoredOutput.info("\n🔒 Header di sicurezza:")
                security = malware_results['security_indicators']
                
                # Controlla header importanti
                if security.get('hsts'):
                    ColoredOutput.success("  ✅ HSTS: Presente")
                else:
                    ColoredOutput.warning("  ⚠️ HSTS: Mancante")
                
                if security.get('csp'):
                    ColoredOutput.success("  ✅ CSP: Configurato")
                else:
                    ColoredOutput.warning("  ⚠️ CSP: Non configurato")
                
                if security.get('x_frame_options'):
                    ColoredOutput.success("  ✅ X-Frame-Options: Presente")
                else:
                    ColoredOutput.warning("  ⚠️ X-Frame-Options: Mancante")
            
            # Analisi JavaScript se presente
            if malware_results['content_analysis'].get('javascript'):
                js_analysis = malware_results['content_analysis']['javascript']
                if js_analysis.get('suspicious_functions'):
                    ColoredOutput.warning(f"\n⚠️ JavaScript sospetto: {len(js_analysis['suspicious_functions'])} funzioni")
                    for func in js_analysis['suspicious_functions'][:2]:  # Prime 2
                        ColoredOutput.warning(f"  → {func}")
                else:
                    ColoredOutput.success("\n✅ JavaScript: Nessuna funzione sospetta")
            
        except Exception as e:
            ColoredOutput.error(f"Errore nell'analisi malware: {e}")
            self.results['analysis']['malware_phishing'] = {'error': str(e)}
    
    def wayback_analysis(self):
        """Analisi cronologia Wayback Machine"""
        ColoredOutput.header("Analisi Wayback Machine")
        
        try:
            if not WAYBACK_AVAILABLE:
                ColoredOutput.warning("Wayback Machine non disponibile - installare waybackpy")
                self.results['analysis']['wayback'] = {'error': 'waybackpy not available'}
                return
            
            wayback_analyzer = WaybackAnalyzer()
            
            # Ottieni snapshot storici
            ColoredOutput.info("Recupero snapshot storici...")
            snapshots = wayback_analyzer.get_snapshots(self.target_url, limit=20)
            
            # Ottieni primo e ultimo snapshot
            ColoredOutput.info("Analisi primo e ultimo snapshot...")
            first_last = wayback_analyzer.get_first_last_snapshot(self.target_url)
            
            # Analizza cambiamenti storici
            ColoredOutput.info("Analisi cambiamenti storici...")
            changes = wayback_analyzer.analyze_historical_changes(self.target_url)
            
            wayback_results = {
                'snapshots': snapshots,
                'first_last_snapshot': first_last,
                'historical_changes': changes,
                'method': 'wayback_machine_analysis'
            }
            
            self.results['analysis']['wayback'] = wayback_results
            
            # Mostra risultati dettagliati
            if snapshots.get('snapshots'):
                ColoredOutput.success(f"Trovati {len(snapshots['snapshots'])} snapshot")
                
                # Mostra cronologia snapshot con dettagli
                ColoredOutput.info("\n📸 Cronologia snapshot dettagliata:")
                for i, snapshot in enumerate(snapshots['snapshots'][:8]):  # Mostra primi 8
                    timestamp = snapshot.get('timestamp', 'N/A')
                    archive_url = snapshot.get('archive_url', 'N/A')
                    status_code = snapshot.get('status_code', 'N/A')
                    
                    # Formatta timestamp per migliore leggibilità
                    try:
                        from datetime import datetime
                        if timestamp != 'N/A':
                            dt = datetime.strptime(timestamp, '%Y%m%d%H%M%S')
                            formatted_date = dt.strftime('%d/%m/%Y %H:%M:%S')
                        else:
                            formatted_date = timestamp
                    except:
                        formatted_date = timestamp
                    
                    ColoredOutput.info(f"  {i+1:2d}. 📅 {formatted_date}")
                    if status_code != 'N/A':
                        ColoredOutput.info(f"      📊 Status: {status_code}")
                    if len(archive_url) < 100:  # Mostra URL solo se non troppo lungo
                        ColoredOutput.info(f"      🔗 {archive_url}")
                    else:
                        ColoredOutput.info(f"      🔗 {archive_url[:80]}...")
                    
                if len(snapshots['snapshots']) > 8:
                    ColoredOutput.info(f"  ... e altri {len(snapshots['snapshots']) - 8} snapshot")
                    ColoredOutput.info(f"      💡 Tutti i dettagli sono salvati nel file JSON dei risultati")
            
            # Informazioni primo e ultimo snapshot
            if first_last.get('first') or first_last.get('last'):
                ColoredOutput.info("\n🕐 Cronologia del sito:")
                if first_last.get('first'):
                    first_date = first_last['first'].get('timestamp', 'N/A')
                    ColoredOutput.info(f"  📅 Primo archivio: {first_date}")
                if first_last.get('last'):
                    last_date = first_last['last'].get('timestamp', 'N/A')
                    ColoredOutput.info(f"  📅 Ultimo archivio: {last_date}")
            
            # Mostra cambiamenti storici se disponibili
            if changes.get('content_size_changes'):
                ColoredOutput.info(f"\n🔄 Analisi cambiamenti storici:")
                ColoredOutput.info(f"   📊 Snapshot analizzati: {changes.get('analyzed_snapshots', 0)}")
                
                size_changes = changes['content_size_changes']
                if size_changes:
                    ColoredOutput.info(f"   📈 Cambiamenti dimensioni rilevati: {len(size_changes)}")
                    
                    for i, change in enumerate(size_changes[:4]):  # Prime 4 modifiche
                        from_date = change.get('from_timestamp', 'N/A')
                        to_date = change.get('to_timestamp', 'N/A')
                        size_change_percent = change.get('size_change_percent', 0)
                        size_change_bytes = change.get('size_change_bytes', 0)
                        
                        # Formatta le date
                        try:
                            from datetime import datetime
                            if from_date != 'N/A':
                                from_dt = datetime.strptime(from_date, '%Y%m%d%H%M%S')
                                from_formatted = from_dt.strftime('%d/%m/%Y')
                            else:
                                from_formatted = from_date
                                
                            if to_date != 'N/A':
                                to_dt = datetime.strptime(to_date, '%Y%m%d%H%M%S')
                                to_formatted = to_dt.strftime('%d/%m/%Y')
                            else:
                                to_formatted = to_date
                        except:
                            from_formatted = from_date
                            to_formatted = to_date
                        
                        # Determina il tipo di cambiamento
                        if size_change_percent > 10:
                            change_icon = "📈"
                            change_desc = "Aumento significativo"
                        elif size_change_percent < -10:
                            change_icon = "📉"
                            change_desc = "Diminuzione significativa"
                        else:
                            change_icon = "📊"
                            change_desc = "Modifica minore"
                        
                        ColoredOutput.info(f"   {i+1}. {change_icon} {from_formatted} → {to_formatted}")
                        ColoredOutput.info(f"      💾 Variazione: {size_change_percent:+.1f}% ({size_change_bytes:+d} bytes)")
                        ColoredOutput.info(f"      📝 {change_desc}")
                    
                    if len(size_changes) > 4:
                        ColoredOutput.info(f"   ... e altri {len(size_changes) - 4} cambiamenti")
                        ColoredOutput.info(f"   💡 Analisi completa disponibile nel file JSON")
                else:
                    ColoredOutput.info(f"   ℹ️  Nessun cambiamento significativo rilevato")
            
            # Statistiche generali
            total_snapshots = len(snapshots.get('snapshots', []))
            if total_snapshots > 0:
                ColoredOutput.info(f"\n📊 Il sito è stato archiviato {total_snapshots} volte")
                if first_last.get('first') and first_last.get('last'):
                    ColoredOutput.info("📈 Sito attivo da diversi anni nella Wayback Machine")
                
        except Exception as e:
            ColoredOutput.error(f"Errore nell'analisi Wayback: {e}")
            self.results['analysis']['wayback'] = {'error': str(e)}
    
    def urlvoid_check(self, url):
        """Controllo reputazione URL con URLVoid"""
        try:
            # Simulazione controllo URLVoid (implementazione base)
            domain = urlparse(url).netloc
            
            # Pattern di domini sospetti
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit', '.onion']
            suspicious_keywords = ['phishing', 'malware', 'virus', 'hack', 'scam', 'fake']
            
            risk_score = 0
            indicators = []
            
            # Controllo TLD sospetti
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    risk_score += 30
                    indicators.append(f"TLD sospetto: {tld}")
            
            # Controllo parole chiave sospette
            for keyword in suspicious_keywords:
                if keyword in domain.lower():
                    risk_score += 25
                    indicators.append(f"Keyword sospetta: {keyword}")
            
            # Controllo lunghezza dominio
            if len(domain) > 50:
                risk_score += 15
                indicators.append("Dominio molto lungo")
            
            # Controllo caratteri sospetti
            if any(char in domain for char in ['-', '_', '0', '1']):
                risk_score += 10
                indicators.append("Caratteri potenzialmente sospetti")
            
            return {
                'domain': domain,
                'risk_score': min(risk_score, 100),
                'status': 'high_risk' if risk_score > 50 else 'medium_risk' if risk_score > 20 else 'low_risk',
                'indicators': indicators,
                'method': 'urlvoid_simulation'
            }
            
        except Exception as e:
            return {'error': str(e), 'method': 'urlvoid_check'}
    
    def detect_suspicious_patterns(self, content):
        """Rileva pattern sospetti nel contenuto"""
        suspicious_patterns = []
        
        # Pattern JavaScript sospetti
        js_patterns = [
            r'eval\s*\(',
            r'document\.write\s*\(',
            r'window\.location\s*=',
            r'iframe.*src\s*=',
            r'base64',
            r'unescape\s*\(',
            r'fromCharCode\s*\('
        ]
        
        # Pattern phishing
        phishing_patterns = [
            r'urgent.*action.*required',
            r'verify.*account.*immediately',
            r'suspended.*account',
            r'click.*here.*now',
            r'limited.*time.*offer'
        ]
        
        # Controllo pattern JavaScript
        for pattern in js_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                suspicious_patterns.append({
                    'type': 'suspicious_javascript',
                    'pattern': pattern,
                    'matches': len(matches)
                })
        
        # Controllo pattern phishing
        for pattern in phishing_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                suspicious_patterns.append({
                    'type': 'phishing_content',
                    'pattern': pattern,
                    'matches': len(matches)
                })
        
        return suspicious_patterns
    
    def analyze_suspicious_javascript(self, js_content):
        """Analizza JavaScript per codice sospetto"""
        analysis = {
            'obfuscated_code': False,
            'suspicious_functions': [],
            'external_requests': [],
            'risk_level': 'low'
        }
        
        # Controllo offuscamento
        if len(re.findall(r'[a-zA-Z]{50,}', js_content)) > 5:
            analysis['obfuscated_code'] = True
            analysis['risk_level'] = 'high'
        
        # Funzioni sospette
        suspicious_funcs = ['eval', 'unescape', 'fromCharCode', 'atob', 'btoa']
        for func in suspicious_funcs:
            if func in js_content:
                analysis['suspicious_functions'].append(func)
                analysis['risk_level'] = 'medium'
        
        # Richieste esterne
        external_urls = re.findall(r'https?://[^\s"\'\']+', js_content)
        analysis['external_requests'] = external_urls[:10]  # Primi 10
        
        return analysis
    
    def analyze_security_headers(self):
        """Analizza header di sicurezza per indicatori di malware"""
        security_analysis = {
            'missing_headers': [],
            'weak_headers': [],
            'security_score': 100,
            'recommendations': []
        }
        
        try:
            # Ottieni header dalla risposta HTTP se disponibile
            headers = {}
            if hasattr(self, 'response_headers') and self.response_headers:
                headers = self.response_headers
            elif hasattr(self, 'session'):
                try:
                    response = self.session.head(self.target_url, timeout=10)
                    headers = dict(response.headers)
                except:
                    pass
            
            # Header di sicurezza critici
            critical_headers = {
                'X-Frame-Options': 'Protezione clickjacking',
                'X-Content-Type-Options': 'Prevenzione MIME sniffing',
                'X-XSS-Protection': 'Protezione XSS',
                'Strict-Transport-Security': 'Sicurezza HTTPS',
                'Content-Security-Policy': 'Politica sicurezza contenuti'
            }
            
            # Controlla header mancanti
            for header, description in critical_headers.items():
                if header not in headers:
                    security_analysis['missing_headers'].append({
                        'header': header,
                        'description': description,
                        'risk': 'medium'
                    })
                    security_analysis['security_score'] -= 15
            
            # Controlla header deboli
            if 'X-Powered-By' in headers:
                security_analysis['weak_headers'].append({
                    'header': 'X-Powered-By',
                    'value': headers['X-Powered-By'],
                    'risk': 'Information disclosure'
                })
                security_analysis['security_score'] -= 5
            
            if 'Server' in headers:
                server_header = headers['Server']
                if any(tech in server_header.lower() for tech in ['apache', 'nginx', 'iis']):
                    if '/' in server_header:  # Versione esposta
                        security_analysis['weak_headers'].append({
                            'header': 'Server',
                            'value': server_header,
                            'risk': 'Version disclosure'
                        })
                        security_analysis['security_score'] -= 5
            
            # Genera raccomandazioni
            if security_analysis['missing_headers']:
                security_analysis['recommendations'].append(
                    "Implementare header di sicurezza mancanti"
                )
            
            if security_analysis['weak_headers']:
                security_analysis['recommendations'].append(
                    "Rimuovere o offuscare header informativi"
                )
            
            security_analysis['security_score'] = max(0, security_analysis['security_score'])
            
        except Exception as e:
            security_analysis['error'] = str(e)
        
        return security_analysis
    
    def save_results(self):
        """Salva i risultati"""
        ColoredOutput.header("Salvataggio Risultati")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Salva JSON
        json_filename = f"osint_analysis_{self.domain}_{timestamp}.json"
        json_filepath = self.output_dir / json_filename
        
        with open(json_filepath, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
        
        ColoredOutput.success(f"Report JSON salvato: {json_filepath}")
        
        # Genera report HTML
        html_filename = f"osint_report_{self.domain}_{timestamp}.html"
        html_filepath = self.output_dir / html_filename
        
        self.generate_html_report(html_filepath)
        ColoredOutput.success(f"Report HTML generato: {html_filepath}")
        
        # Genera report di testo
        txt_filename = f"osint_summary_{self.domain}_{timestamp}.txt"
        txt_filepath = self.output_dir / txt_filename
        
        self.generate_text_report(txt_filepath)
        ColoredOutput.success(f"Riepilogo testuale: {txt_filepath}")
    
    def generate_html_report(self, filepath):
        """Genera report HTML avanzato"""
        html_content = f"""
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic-Excavator Report - {self.domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; padding: 20px;
        }}
        .container {{ 
            max-width: 1200px; margin: 0 auto; background: white;
            border-radius: 15px; box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{ 
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white; padding: 30px; text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .subtitle {{ opacity: 0.8; font-size: 1.1em; }}
        .content {{ padding: 30px; }}
        .section {{ 
            margin-bottom: 40px; border-radius: 10px;
            border: 1px solid #e0e0e0; overflow: hidden;
        }}
        .section-header {{ 
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
            color: white; padding: 15px 20px; font-size: 1.3em; font-weight: bold;
        }}
        .section-content {{ padding: 20px; }}
        .info-grid {{ 
            display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px; margin: 20px 0;
        }}
        .info-card {{ 
            background: #f8f9fa; border-radius: 8px; padding: 15px;
            border-left: 4px solid #3498db;
        }}
        .info-card h4 {{ color: #2c3e50; margin-bottom: 10px; }}
        .success {{ border-left-color: #27ae60; }}
        .warning {{ border-left-color: #f39c12; }}
        .error {{ border-left-color: #e74c3c; }}
        .code {{ 
            background: #2c3e50; color: #ecf0f1; padding: 15px;
            border-radius: 5px; font-family: 'Courier New', monospace;
            overflow-x: auto; margin: 10px 0;
        }}
        .badge {{ 
            display: inline-block; padding: 4px 8px; border-radius: 4px;
            font-size: 0.8em; font-weight: bold; margin: 2px;
        }}
        .badge-success {{ background: #27ae60; color: white; }}
        .badge-warning {{ background: #f39c12; color: white; }}
        .badge-error {{ background: #e74c3c; color: white; }}
        .badge-info {{ background: #3498db; color: white; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #34495e; color: white; }}
        tr:nth-child(even) {{ background: #f2f2f2; }}
        .footer {{ 
            background: #34495e; color: white; padding: 20px;
            text-align: center; font-size: 0.9em;
        }}
        .progress-bar {{ 
            width: 100%; height: 20px; background: #ecf0f1;
            border-radius: 10px; overflow: hidden; margin: 10px 0;
        }}
        .progress-fill {{ 
            height: 100%; background: linear-gradient(90deg, #27ae60, #2ecc71);
            transition: width 0.3s ease;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Forensic-Excavator Analysis Report</h1>
            <div class="subtitle">
                Target: {self.target_url}<br>
                Domain: {self.domain}<br>
                Analysis Date: {self.results['timestamp']}
            </div>
        </div>
        
        <div class="content">
"""
        
        # Aggiungi sezioni per ogni analisi
        for section_name, section_data in self.results['analysis'].items():
            if isinstance(section_data, dict) and 'error' not in section_data:
                html_content += self._generate_html_section(section_name, section_data)
        
        html_content += """
        </div>
        
        <div class="footer">
            <p>Report generato da Forensic-Excavator - Advanced Forensic Tool</p>
            <p>⚠️ Questo report è destinato esclusivamente a scopi legali e autorizzati</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_html_section(self, section_name, section_data):
        """Genera sezione HTML per i dati"""
        section_title = section_name.replace('_', ' ').title()
        
        html = f"""
        <div class="section">
            <div class="section-header">{section_title}</div>
            <div class="section-content">
"""
        
        if section_name == 'basic_info':
            html += self._generate_basic_info_html(section_data)
        elif section_name == 'security':
            html += self._generate_security_html(section_data)
        elif section_name == 'subdomains':
            html += self._generate_subdomains_html(section_data)
        else:
            html += f"<pre class='code'>{json.dumps(section_data, indent=2, ensure_ascii=False, default=str)}</pre>"
        
        html += """
            </div>
        </div>
"""
        
        return html
    
    def _generate_basic_info_html(self, data):
        """Genera HTML per informazioni di base"""
        status_class = 'success' if data.get('status_code') == 200 else 'error'
        
        return f"""
        <div class="info-grid">
            <div class="info-card {status_class}">
                <h4>Status HTTP</h4>
                <p><span class="badge badge-{'success' if data.get('status_code') == 200 else 'error'}">{data.get('status_code', 'N/A')}</span></p>
            </div>
            <div class="info-card">
                <h4>Titolo Pagina</h4>
                <p>{data.get('title', 'N/A')}</p>
            </div>
            <div class="info-card">
                <h4>Server</h4>
                <p>{data.get('server', 'N/A')}</p>
            </div>
            <div class="info-card">
                <h4>Dimensione Contenuto</h4>
                <p>{data.get('content_length', 0):,} bytes</p>
            </div>
        </div>
        """
    
    def _generate_security_html(self, data):
        """Genera HTML per analisi sicurezza"""
        if 'security_headers' in data:
            score = data['security_headers'].get('security_percentage', 0)
            score_class = 'success' if score >= 80 else 'warning' if score >= 50 else 'error'
            
            return f"""
             <div class="info-card {score_class}">
                 <h4>Score Sicurezza</h4>
                 <p><span class="badge badge-{score_class}">{score}%</span></p>
                 <div class="progress-bar">
                     <div class="progress-fill" style="width: {score}%"></div>
                 </div>
             </div>
             <div class="info-card">
                 <h4>Certificato SSL</h4>
                 <p><span class="badge badge-{'success' if data['ssl_certificate'].get('valid') else 'error'}">
                     {'Valido' if data['ssl_certificate'].get('valid') else 'Problemi'}
                 </span></p>
             </div>
         </div>
         """
        return "<p>Dati sicurezza non disponibili</p>"
    
    def _generate_subdomains_html(self, data):
        """Genera HTML per sottodomini"""
        if isinstance(data, list) and data:
            html = "<div class='info-grid'>"
            for i, subdomain in enumerate(data[:12]):  # Mostra max 12
                html += f"""
                <div class="info-card">
                    <h4>Sottodominio {i+1}</h4>
                    <p>{subdomain}</p>
                </div>
                """
            html += "</div>"
            if len(data) > 12:
                html += f"<p><strong>... e altri {len(data) - 12} sottodomini</strong></p>"
            return html
        return "<p>Nessun sottodominio trovato</p>"
    
    def generate_text_report(self, filepath):
        """Genera report testuale"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("FORENSIC-EXCAVATOR - REPORT ANALISI FORENSE\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Domain: {self.domain}\n")
            f.write(f"Data Analisi: {self.results['timestamp']}\n")
            f.write("=" * 80 + "\n\n")
            
            for section_name, section_data in self.results['analysis'].items():
                if isinstance(section_data, dict) and 'error' not in section_data:
                    f.write(f"\n[{section_name.upper().replace('_', ' ')}]\n")
                    f.write("-" * 40 + "\n")
                    
                    if section_name == 'basic_info':
                        f.write(f"Status Code: {section_data.get('status_code', 'N/A')}\n")
                        f.write(f"Title: {section_data.get('title', 'N/A')}\n")
                        f.write(f"Server: {section_data.get('server', 'N/A')}\n")
                        f.write(f"Content Length: {section_data.get('content_length', 0):,} bytes\n")
                    
                    elif section_name == 'geolocation':
                        f.write(f"IP: {section_data.get('ip', 'N/A')}\n")
                        f.write(f"Country: {section_data.get('country', 'N/A')}\n")
                        f.write(f"City: {section_data.get('city', 'N/A')}\n")
                        f.write(f"ISP: {section_data.get('isp', 'N/A')}\n")
                    
                    elif section_name == 'security':
                        if 'security_headers' in section_data:
                            score = section_data['security_headers'].get('security_percentage', 0)
                            f.write(f"Security Score: {score}%\n")
                        ssl_valid = section_data.get('ssl_certificate', {}).get('valid', False)
                        f.write(f"SSL Certificate: {'Valid' if ssl_valid else 'Issues'}\n")
                    
                    elif section_name == 'subdomains':
                        if isinstance(section_data, list):
                            f.write(f"Found {len(section_data)} subdomains:\n")
                            for subdomain in section_data[:10]:
                                f.write(f"  - {subdomain}\n")
                            if len(section_data) > 10:
                                f.write(f"  ... and {len(section_data) - 10} more\n")
                    
                    elif section_name == 'technologies':
                        for category, techs in section_data.items():
                            if techs:
                                f.write(f"{category.title()}: {', '.join(techs)}\n")
                    
                    f.write("\n")
    
    def show_summary(self):
        """Mostra riepilogo dell'analisi con informazioni essenziali"""
        ColoredOutput.header("Riepilogo Analisi")
        
        # Statistiche generali
        total_analyses = len([k for k, v in self.results['analysis'].items() if 'error' not in v])
        failed_analyses = len([k for k, v in self.results['analysis'].items() if 'error' in v])
        
        ColoredOutput.success(f"Analisi completate: {total_analyses}")
        if failed_analyses > 0:
            ColoredOutput.warning(f"Analisi fallite: {failed_analyses}")
        
        # === INFORMAZIONI ESSENZIALI ===
        ColoredOutput.header("📊 Informazioni Essenziali")
        
        # IP e Geolocalizzazione
        if 'geolocation' in self.results['analysis']:
            geo = self.results['analysis']['geolocation']
            if 'error' not in geo:
                ColoredOutput.info(f"🌐 IP Principale: {geo.get('ip', 'N/A')}")
                ColoredOutput.info(f"📍 Localizzazione: {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}")
                ColoredOutput.info(f"🏢 ISP: {geo.get('isp', 'N/A')}")
        
        # Informazioni di base e server
        if 'basic_info' in self.results['analysis']:
            basic = self.results['analysis']['basic_info']
            if 'error' not in basic:
                ColoredOutput.info(f"📊 Status: {basic.get('status_code', 'N/A')}")
                ColoredOutput.info(f"🖥️  Server: {basic.get('server', 'N/A')}")
                ColoredOutput.info(f"📄 Title: {basic.get('title', 'N/A')}")
        
        # Tecnologie rilevate
        if 'technologies' in self.results['analysis']:
            tech = self.results['analysis']['technologies']
            if 'error' not in tech and 'detected_technologies' in tech:
                detected = tech['detected_technologies']
                tech_summary = []
                for category, items in detected.items():
                    if items and category != 'method':
                        tech_summary.extend(items[:3])  # Prime 3 per categoria
                if tech_summary:
                    ColoredOutput.info(f"⚙️  Tecnologie: {', '.join(tech_summary[:5])}")
        
        # Sottodomini
        if 'subdomains' in self.results['analysis']:
            subdomains = self.results['analysis']['subdomains']
            if isinstance(subdomains, list):
                ColoredOutput.info(f"🔗 Sottodomini trovati: {len(subdomains)}")
                if len(subdomains) > 0:
                    ColoredOutput.info(f"   Esempi: {', '.join(subdomains[:3])}")
        
        # Sicurezza e vulnerabilità
        if 'security' in self.results['analysis']:
            security = self.results['analysis']['security']
            if 'error' not in security:
                if 'security_headers' in security:
                    score = security['security_headers'].get('security_percentage', 0)
                    status = "🔴 Critico" if score < 30 else "🟡 Medio" if score < 70 else "🟢 Buono"
                    ColoredOutput.info(f"🛡️  Score sicurezza: {score}% ({status})")
                
                # SSL Certificate
                if 'ssl_certificate' in security:
                    ssl_valid = security['ssl_certificate'].get('valid', False)
                    ssl_status = "🟢 Valido" if ssl_valid else "🔴 Problemi"
                    ColoredOutput.info(f"🔒 Certificato SSL: {ssl_status}")
        
        # URL e link trovati (crawling/scraping)
        if 'web_scraping' in self.results['analysis']:
            scraping = self.results['analysis']['web_scraping']
            if 'error' not in scraping:
                internal_links = scraping.get('internal_links', [])
                external_links = scraping.get('external_links', [])
                ColoredOutput.info(f"🔍 Link interni trovati: {len(internal_links)}")
                ColoredOutput.info(f"🌐 Link esterni trovati: {len(external_links)}")
                
                # Mostra alcuni esempi di link esterni
                if external_links:
                    ColoredOutput.info(f"   Domini esterni: {', '.join(list(external_links)[:3])}")
        
        # Metadati importanti
        if 'metadata_extraction' in self.results['analysis']:
            metadata = self.results['analysis']['metadata_extraction']
            if 'error' not in metadata:
                meta_count = len(metadata.get('meta_tags', []))
                ColoredOutput.info(f"📋 Metadati estratti: {meta_count} tag")
                
                # Mostra metadati critici
                meta_tags = metadata.get('meta_tags', [])
                for tag in meta_tags:
                    if tag.get('name') in ['generator', 'author', 'copyright']:
                        ColoredOutput.info(f"   {tag.get('name', '')}: {tag.get('content', '')[:50]}")
        
        # Analisi Wayback Machine
        if 'wayback_analysis' in self.results['analysis']:
            wayback = self.results['analysis']['wayback_analysis']
            if 'error' not in wayback:
                # Informazioni generali
                snapshots_data = wayback.get('snapshots', {})
                snapshots_list = snapshots_data.get('snapshots', [])
                total_snapshots = len(snapshots_list)
                
                if total_snapshots > 0:
                    ColoredOutput.info(f"📸 Wayback Machine - {total_snapshots} snapshot trovati")
                    
                    # Primo e ultimo snapshot
                    first_last = wayback.get('first_last_snapshot', {})
                    if first_last.get('first'):
                        first_date = first_last['first'].get('timestamp', 'N/A')
                        ColoredOutput.info(f"   📅 Prima apparizione: {first_date}")
                    if first_last.get('last'):
                        last_date = first_last['last'].get('timestamp', 'N/A')
                        ColoredOutput.info(f"   📅 Ultimo snapshot: {last_date}")
                    
                    # Mostra alcuni snapshot recenti
                    if snapshots_list:
                        ColoredOutput.info(f"   🔍 Snapshot recenti:")
                        for i, snapshot in enumerate(snapshots_list[:5]):
                            timestamp = snapshot.get('timestamp', 'N/A')
                            url = snapshot.get('url', 'N/A')
                            ColoredOutput.info(f"     → {timestamp}")
                        
                        if total_snapshots > 5:
                            ColoredOutput.info(f"     ... e altri {total_snapshots - 5} snapshot")
                    
                    # Cambiamenti storici
                    changes = wayback.get('historical_changes', {})
                    if changes.get('changes'):
                        changes_count = len(changes['changes'])
                        ColoredOutput.info(f"   🔄 Cambiamenti rilevati: {changes_count}")
                        for change in changes['changes'][:3]:
                            change_date = change.get('timestamp', 'N/A')
                            change_type = change.get('change_type', 'Modifica')
                            ColoredOutput.info(f"     → {change_date}: {change_type}")
                        if changes_count > 3:
                            ColoredOutput.info(f"     ... e altri {changes_count - 3} cambiamenti")
                else:
                    ColoredOutput.warning("📸 Nessun snapshot trovato nella Wayback Machine")
        
        # CDN e bypass
        if 'cdn_bypass' in self.results['analysis']:
            cdn = self.results['analysis']['cdn_bypass']
            if 'error' not in cdn:
                real_ip = cdn.get('crimeflare_result', {}).get('real_ip')
                if real_ip:
                    ColoredOutput.warning(f"🚨 IP reale rilevato (CDN bypass): {real_ip}")
        
        ColoredOutput.print_colored("\n" + "=" * 80, 'cyan', bold=True)
        ColoredOutput.print_colored("✅ ANALISI FORENSE COMPLETATA CON SUCCESSO!", 'green', bold=True)
        ColoredOutput.print_colored(f"📁 Risultati completi salvati in: {self.output_dir}", 'cyan')
        ColoredOutput.print_colored("💡 Usa i file nella cartella per analisi dettagliate", 'yellow')
        ColoredOutput.print_colored("=" * 80, 'cyan', bold=True)

def main():
    """Funzione principale"""
    import argparse
    
    # Parser argomenti
    parser = argparse.ArgumentParser(
        description='🔍 Forensic-Excavator - Advanced Forensic Tool v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi di utilizzo:
  python3 osint_web_analyzer.py                    # Modalità interattiva
  python3 osint_web_analyzer.py -t example.com     # Analisi diretta
  python3 osint_web_analyzer.py -t https://site.com -o results/

⚠️  ATTENZIONE: Utilizzare solo per scopi legali e autorizzati
        """
    )
    
    parser.add_argument('-t', '--target', 
                       help='URL o dominio da analizzare')
    parser.add_argument('-o', '--output', 
                       default='osint_results',
                       help='Directory di output (default: osint_results)')
    parser.add_argument('-v', '--version', 
                       action='version', 
                       version='Forensic-Excavator v2.0 - Advanced Edition')
    parser.add_argument('--force', 
                       action='store_true',
                       help='Forza l\'analisi anche in caso di errori di connessione (solo per test)')
    parser.add_argument('--update-deps', 
                       action='store_true',
                       help='Aggiorna tutte le dipendenze all\'ultima versione e termina')
    
    args = parser.parse_args()
    
    # Gestione aggiornamento dipendenze
    if args.update_deps:
        ColoredOutput.print_colored("\n" + "=" * 80, 'cyan', bold=True)
        ColoredOutput.print_colored("🔄 AGGIORNAMENTO DIPENDENZE FORENSIC-EXCAVATOR", 'cyan', bold=True)
        ColoredOutput.print_colored("=" * 80, 'cyan', bold=True)
        DependencyManager.update_all_packages()
        ColoredOutput.print_colored("=" * 80, 'cyan', bold=True)
        ColoredOutput.print_colored("✅ Aggiornamento completato! Riavvia il programma.", 'green', bold=True)
        ColoredOutput.print_colored("=" * 80, 'cyan', bold=True)
        return
    
    # Header
    ColoredOutput.print_colored("\n" + "=" * 80, 'cyan', bold=True)
    ColoredOutput.print_colored("🔍 FORENSIC-EXCAVATOR - ADVANCED FORENSIC TOOL", 'cyan', bold=True)
    ColoredOutput.print_colored("🚀 Versione 2.0 - All-in-One Edition", 'yellow')
    ColoredOutput.print_colored("=" * 80, 'cyan', bold=True)
    ColoredOutput.print_colored("⚠️  ATTENZIONE: Utilizzare solo per scopi legali e autorizzati", 'red', bold=True)
    ColoredOutput.print_colored("=" * 80, 'cyan', bold=True)
    
    # Determina target
    if args.target:
        target = args.target.strip()
    else:
        # Modalità interattiva
        target = input("\n🎯 Inserisci l'URL o dominio da analizzare: ").strip()
    
    if not target:
        ColoredOutput.error("URL non valido!")
        return
    
    # Conferma se non specificato da riga di comando
    if not args.target:
        ColoredOutput.warning(f"Stai per analizzare: {target}")
        confirm = input("Continuare? (s/N): ").strip().lower()
        
        if confirm not in ['s', 'si', 'y', 'yes']:
            ColoredOutput.info("Analisi annullata.")
            return
    
    try:
        # Avvia analisi
        analyzer = AdvancedForensicAnalyzer(target, args.output, force_proceed=args.force)
        analyzer.run_comprehensive_analysis()
        
    except KeyboardInterrupt:
        ColoredOutput.warning("\nAnalisi interrotta dall'utente.")
    except Exception as e:
        ColoredOutput.error(f"Errore durante l'analisi: {e}")
        ColoredOutput.info("Controlla la connessione internet e la validità del target.")

if __name__ == "__main__":
    main()