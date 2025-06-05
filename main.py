import threading
import requests
import os
import tldextract
import socket
from tkinter import filedialog, PhotoImage, BOTH, X, W, CENTER
from PIL import Image, ImageTk
import dns.resolver
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

# Screenshot folder
SCREENSHOT_DIR = "screenshots"
os.makedirs(SCREENSHOT_DIR, exist_ok=True)
TIMEOUT = 3

WAF_SIGNATURES = {
    "Cloudflare": "cloudflare",
    "Akamai": "akamai",
    "AWS": "aws",
    "Sucuri": "sucuri",
    "F5": "bigip",
}

def take_screenshot(url, filename):
    try:
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        driver = webdriver.Chrome(options=options)
        driver.set_window_size(1200, 800)
        driver.get(url)
        driver.save_screenshot(filename)
        driver.quit()
    except Exception as e:
        print(f"Screenshot error: {e}")

def detect_waf(headers):
    for waf, signature in WAF_SIGNATURES.items():
        if any(signature in str(value).lower() for value in headers.values()):
            return waf
    return "None"

def is_live(domain):
    try:
        socket.gethostbyname(domain)
        response = requests.get(f"http://{domain}", timeout=TIMEOUT)
        return response.status_code, response.headers
    except:
        return None, None

def bruteforce_subdomains(domain, wordlist, output):
    ext = tldextract.extract(domain)
    base = f"{ext.domain}.{ext.suffix}"
    with open(wordlist) as f:
        for line in f:
            sub = line.strip()
            full_domain = f"{sub}.{base}"
            status, headers = is_live(full_domain)
            if status:
                waf = detect_waf(headers)
                output(f"[LIVE] {full_domain} | Status: {status} | WAF: {waf}")
                ss_path = os.path.join(SCREENSHOT_DIR, f"{full_domain}.png")
                take_screenshot(f"http://{full_domain}", ss_path)
            else:
                output(f"[DEAD] {full_domain}")

def bruteforce_directories(domain, wordlist, output):
    with open(wordlist) as f:
        for line in f:
            path = line.strip()
            url = f"http://{domain}/{path}"
            try:
                r = requests.get(url, timeout=TIMEOUT)
                if r.status_code < 400:
                    output(f"[FOUND] {url} | Status: {r.status_code}")
            except:
                continue

class ReconXApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ReconX - Subdomain & Directory Bruteforcer")

        self.style = ttk.Style(theme="darkly")
        self.frame = ttk.Frame(root, padding=20)
        self.frame.pack(fill=BOTH, expand=True)

        # Load logo with resizing and error handling
        try:
            logo_path = "Assets/logo.png"
            if os.path.exists(logo_path):
                img = Image.open(logo_path)
                max_size = (200, 80)
                img.thumbnail(max_size, Image.ANTIALIAS)
                self.logo = ImageTk.PhotoImage(img)
                ttk.Label(self.frame, image=self.logo).pack(pady=(0, 10))
            else:
                print(f"Logo file not found at: {logo_path}")
        except Exception as e:
            print(f"Error loading logo: {e}")

        ttk.Label(self.frame, text="Target Domain", font=("Segoe UI", 12, "bold")).pack(anchor=W)
        self.domain_entry = ttk.Entry(self.frame, width=50, bootstyle="info")
        self.domain_entry.pack(pady=5, fill=X)

        ttk.Label(self.frame, text="Subdomain Wordlist", font=("Segoe UI", 10, "bold")).pack(anchor=W)
        ttk.Button(self.frame, text="Select Subdomain Wordlist", command=self.load_sublist, bootstyle="primary").pack(fill=X)

        ttk.Label(self.frame, text="Directory Wordlist", font=("Segoe UI", 10, "bold")).pack(anchor=W, pady=(10, 0))
        ttk.Button(self.frame, text="Select Directory Wordlist", command=self.load_dirlist, bootstyle="primary").pack(fill=X)

        ttk.Button(self.frame, text="Start Scan", command=self.start_scan, bootstyle="success-outline").pack(pady=15, fill=X)

        self.output_box = ttk.Text(self.frame, height=15, font=("Consolas", 10))
        self.output_box.pack(fill=BOTH, expand=True, pady=(10, 0))

        self.footer = ttk.Label(self.frame, text="Developed by abhijithmr226 · GitHub.com/abhijithmr226",
                                font=("Segoe UI", 9), bootstyle="secondary")
        self.footer.pack(anchor=CENTER, pady=(10, 0))

        self.sub_wordlist = ""
        self.dir_wordlist = ""

    def load_sublist(self):
        self.sub_wordlist = filedialog.askopenfilename(title="Select Subdomain Wordlist")
        self.output(f"Loaded Subdomain Wordlist: {self.sub_wordlist}")

    def load_dirlist(self):
        self.dir_wordlist = filedialog.askopenfilename(title="Select Directory Wordlist")
        self.output(f"Loaded Directory Wordlist: {self.dir_wordlist}")

    def output(self, text):
        self.output_box.insert(ttk.END, text + "\n")
        self.output_box.see(ttk.END)

    def start_scan(self):
        domain = self.domain_entry.get().strip()
        if not domain or not self.sub_wordlist or not self.dir_wordlist:
            self.output("Error: Provide domain and both wordlists.")
            return
        threading.Thread(target=self.run_scan, args=(domain,), daemon=True).start()

    def run_scan(self, domain):
        self.output("Starting Subdomain Scan...")
        bruteforce_subdomains(domain, self.sub_wordlist, self.output)

        self.output("\nStarting Directory Scan...")
        bruteforce_directories(domain, self.dir_wordlist, self.output)

        self.output("\nScan Complete.")


if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    app = ReconXApp(root)
    root.mainloop()
