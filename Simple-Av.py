import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import requests
import hashlib
import os
import threading
import time
import json
from datetime import datetime

class SimpleAV:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SimpleAV - Antivirus Scanner")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # VirusTotal API Key
        self.api_key = "Pls Paste youre Virustotal api here"
        self.api_url = "https://www.virustotal.com/vtapi/v2/file/report"
        
        # Scanning variables
        self.scanning = False
        self.scan_results = []
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="SimpleAV Scanner", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Scan buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=1, column=0, columnspan=3, pady=(0, 10), sticky=(tk.W, tk.E))
        
        # Scan file button
        self.scan_file_btn = ttk.Button(buttons_frame, text="Datei scannen", 
                                       command=self.scan_file)
        self.scan_file_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Scan folder button
        self.scan_folder_btn = ttk.Button(buttons_frame, text="Ordner scannen", 
                                         command=self.scan_folder)
        self.scan_folder_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Stop scan button
        self.stop_btn = ttk.Button(buttons_frame, text="Scan stoppen", 
                                  command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side=tk.LEFT)
        
        # Progress bar
        progress_frame = ttk.Frame(main_frame)
        progress_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        
        self.status_label = ttk.Label(progress_frame, text="Bereit zum Scannen")
        self.status_label.grid(row=0, column=1)
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(main_frame, text="Scan-Statistiken", padding="10")
        stats_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        stats_frame.columnconfigure(1, weight=1)
        stats_frame.columnconfigure(3, weight=1)
        
        ttk.Label(stats_frame, text="Gescannte Dateien:").grid(row=0, column=0, sticky=tk.W)
        self.scanned_count = ttk.Label(stats_frame, text="0")
        self.scanned_count.grid(row=0, column=1, sticky=tk.W, padx=(10, 20))
        
        ttk.Label(stats_frame, text="Bedrohungen:").grid(row=0, column=2, sticky=tk.W)
        self.threats_count = ttk.Label(stats_frame, text="0", foreground="red")
        self.threats_count.grid(row=0, column=3, sticky=tk.W, padx=(10, 0))
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Scan-Ergebnisse", padding="10")
        results_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Results text widget with scrollbar
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, width=80)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Clear results button
        clear_btn = ttk.Button(results_frame, text="Ergebnisse löschen", 
                              command=self.clear_results)
        clear_btn.grid(row=1, column=0, pady=(10, 0), sticky=tk.E)
        
    def get_file_hash(self, filepath):
        """Calculate SHA-256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            return None
            
    def check_file_virustotal(self, filepath):
        """Check file against VirusTotal API"""
        try:
            file_hash = self.get_file_hash(filepath)
            if not file_hash:
                return {"error": "Fehler beim Berechnen des Hashes"}
                
            params = {
                'apikey': self.api_key,
                'resource': file_hash
            }
            
            response = requests.get(self.api_url, params=params, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result['response_code'] == 1:  # File found in database
                    return {
                        'found': True,
                        'positives': result['positives'],
                        'total': result['total'],
                        'scan_date': result['scan_date'],
                        'permalink': result['permalink']
                    }
                else:
                    return {'found': False, 'message': 'Datei nicht in VirusTotal-Datenbank gefunden'}
            else:
                return {"error": f"API-Fehler: {response.status_code}"}
                
        except requests.exceptions.Timeout:
            return {"error": "Timeout bei VirusTotal-Anfrage"}
        except Exception as e:
            return {"error": f"Fehler bei VirusTotal-Anfrage: {str(e)}"}
            
    def scan_single_file(self, filepath):
        """Scan a single file"""
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        
        self.log_result(f"\n--- Scanne: {filename} ({filesize} Bytes) ---")
        
        # Check with VirusTotal
        vt_result = self.check_file_virustotal(filepath)
        
        if 'error' in vt_result:
            self.log_result(f"❌ {vt_result['error']}")
            return False
            
        if vt_result['found']:
            positives = vt_result['positives']
            total = vt_result['total']
            
            if positives > 0:
                self.log_result(f"🚨 BEDROHUNG ERKANNT! ({positives}/{total} Engines)")
                self.log_result(f"   Scan-Datum: {vt_result['scan_date']}")
                self.log_result(f"   Details: {vt_result['permalink']}")
                return True
            else:
                self.log_result(f"✅ Sauber ({positives}/{total} Engines)")
                return False
        else:
            self.log_result(f"ℹ️ {vt_result['message']}")
            return False
            
    def scan_file(self):
        """Scan selected file"""
        filepath = filedialog.askopenfilename(
            title="Datei zum Scannen auswählen",
            filetypes=[("Alle Dateien", "*.*")]
        )
        
        if filepath:
            threading.Thread(target=self.perform_file_scan, args=(filepath,), daemon=True).start()
            
    def scan_folder(self):
        """Scan selected folder"""
        folder_path = filedialog.askdirectory(title="Ordner zum Scannen auswählen")
        
        if folder_path:
            threading.Thread(target=self.perform_folder_scan, args=(folder_path,), daemon=True).start()
            
    def perform_file_scan(self, filepath):
        """Perform file scan in separate thread"""
        self.start_scan()
        
        try:
            threat_found = self.scan_single_file(filepath)
            self.update_stats(1, 1 if threat_found else 0)
            
        except Exception as e:
            self.log_result(f"❌ Fehler beim Scannen: {str(e)}")
            
        finally:
            self.finish_scan()
            
    def perform_folder_scan(self, folder_path):
        """Perform folder scan in separate thread"""
        self.start_scan()
        
        scanned = 0
        threats = 0
        
        try:
            for root, dirs, files in os.walk(folder_path):
                if not self.scanning:
                    break
                    
                for file in files:
                    if not self.scanning:
                        break
                        
                    filepath = os.path.join(root, file)
                    
                    try:
                        # Skip very large files (>100MB) to avoid API limits
                        if os.path.getsize(filepath) > 100 * 1024 * 1024:
                            self.log_result(f"⏭️ Überspringe große Datei: {file}")
                            continue
                            
                        threat_found = self.scan_single_file(filepath)
                        scanned += 1
                        if threat_found:
                            threats += 1
                            
                        self.update_stats(scanned, threats)
                        
                        # Small delay to respect API rate limits
                        time.sleep(0.5)
                        
                    except Exception as e:
                        self.log_result(f"❌ Fehler bei {file}: {str(e)}")
                        
        except Exception as e:
            self.log_result(f"❌ Fehler beim Ordner-Scan: {str(e)}")
            
        finally:
            self.finish_scan()
            
    def start_scan(self):
        """Start scanning process"""
        self.scanning = True
        self.scan_file_btn.config(state="disabled")
        self.scan_folder_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress.start()
        self.status_label.config(text="Scannen...")
        
    def finish_scan(self):
        """Finish scanning process"""
        self.scanning = False
        self.scan_file_btn.config(state="normal")
        self.scan_folder_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.progress.stop()
        self.status_label.config(text="Scan abgeschlossen")
        self.log_result(f"\n=== Scan abgeschlossen um {datetime.now().strftime('%H:%M:%S')} ===")
        
    def stop_scan(self):
        """Stop current scan"""
        self.scanning = False
        self.log_result("\n⏹️ Scan wurde gestoppt")
        
    def update_stats(self, scanned, threats):
        """Update scan statistics"""
        self.root.after(0, lambda: self.scanned_count.config(text=str(scanned)))
        self.root.after(0, lambda: self.threats_count.config(text=str(threats)))
        
    def log_result(self, message):
        """Log result to text widget"""
        def update_text():
            self.results_text.insert(tk.END, message + "\n")
            self.results_text.see(tk.END)
            
        self.root.after(0, update_text)
        
    def clear_results(self):
        """Clear results text"""
        self.results_text.delete(1.0, tk.END)
        self.scanned_count.config(text="0")
        self.threats_count.config(text="0")
        
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = SimpleAV()
    app.run()
