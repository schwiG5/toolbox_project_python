from flask import Flask, request, render_template_string, render_template
import re
from flask import Flask, request, render_template_string, render_template, send_file, session
import platform
import subprocess
import socket
import whois 
import nmap
import requests
import os
from io import BytesIO
from xhtml2pdf import pisa


app = Flask(__name__)

# Template HTML pour la page d'accueil
HOME_PAGE = '''
<!doctype html>
<html>
<head>
  <title>Scanner de réseau et Test de Mot de Passe</title>
  <style>
    body {
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      font-family: Arial, sans-serif;
      background-color: #2b312a;
    }
    .container {
      background: #484b47;
      padding: 20px;
      border-radius: 10px;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
      max-width: 500px;
      width: 100%;
    }
    h1 {
      margin-bottom: 20px;
      text-align: center;
      color: aliceblue;
    }
    .form-group {
      margin-bottom: 15px;
    }
    .form-group label {
      display: block;
      margin-bottom: 5px;
      color: aliceblue;
    }
    .form-group input[type="text"],
    .form-group input[type="file"],
    .form-group input[type="password"] {
      width: 100%;
      padding: 8px;
      box-sizing: border-box;
      border: 1px solid #ccc;
      border-radius: 5px;
    }
    .form-group input[type="checkbox"] {
      margin-right: 10px;
    }
    button {
      display: block;
      width: 100%;
      padding: 10px;
      background: #007bff;
      color: #fff;
      border: none;
      border-radius: 5px;
      cursor: pointer;
      font-size: 16px;
    }
    button:hover {
      background: #0056b3;
    }

    #flex_options, #flex_fuzz{
      display: flex;
      gap: 20px;
      flex-direction: row;
    }
    #port_flex{
      display: flex;
      align-content: stretch;
      justify-content: center;
      align-items: flex-start;
    }
    /* Styles pour l'élément de chargement */
    #loading {
      display: none; /* Masquer par défaut */
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      justify-content: center;
      align-items: center;
      background-color: rgba(0, 0, 0, 0.5);
      z-index: 9999; /* Assure que l'élément de chargement est au-dessus de tout */
    }

    #loading p {
      color: white;
    }
  </style>
  <script>
    function showLoading() {
      document.getElementById("loading").style.display = "flex";
      setTimeout(function() {
        document.getElementById("loading").style.display = "none";
      }, 3000); // Minimum 3 seconds delay
      return true; // Continuer avec la soumission du formulaire
    }
  </script>

</head>
<body>
  <div class="container">
    <h1>BoxyBox</h1>
    <form action="/scan" method="post" enctype="multipart/form-data" onsubmit="showLoading()">
      <div class="form-group">
        <label for="address">Adresse (IP ou URL)</label>
        <input type="text" name="address" id="address" placeholder="192.168.1.1 ou www.example.com">
      </div>
      <div class="form-group">
        <div id="port_flex">
          <input type="checkbox" name="port_scan" id="port_scan">
          <label for="port_scan">Scan de ports</label>
        </div>
        <input type="text" name="port_range" placeholder="ex. 20-80" id="port_range">
        <label for="port_range">Plage de ports (ex. 20-80):</label>
      </div>
      <div id="flex_options">
        <div class="form-group">
          <input type="checkbox" name="ping" id="ping">
          <label for="ping">Ping</label>
        </div>
        <div class="form-group">
          <input type="checkbox" name="resolve_dns" id="resolve_dns">
          <label for="resolve_dns">Résoudre DNS</label>
        </div>
        <div class="form-group">
          <input type="checkbox" name="whois" id="whois">
          <label for="whois">Whois</label>
        </div>
        <div class="form-group">
          <input type="checkbox" name="service_scan" id="service_scan">
          <label for="service_scan">Scan des services</label>
        </div>
        <div class="form-group">
          <input type="checkbox" name="tcp_scan" id="tcp_scan">
          <label for="tcp_scan">Scan TCP</label>
        </div>
        <div class="form-group">
          <input type="checkbox" name="udp_scan" id="udp_scan">
          <label for="udp_scan">Scan UDP</label>
        </div>
        <div class="form-group">
          <input type="checkbox" name="ping_sweep" id="ping_sweep">
          <label for="ping_sweep">Ping Sweep</label>
        </div>
        <div class="form-group">
          <input type="checkbox" name="vuln_scan" id="vuln_scan">
          <label for="vuln_scan">Vuln Scan</label>
        </div>
      </div>
      <div id=flex_fuzz>
        <div class="form-group">
          <input type="file" style="color: aliceblue; border: none; margin:10px" name="dir_file" id="dir_file" accept=".txt">
          <label for="dir_file" >Fichier de répertoires (txt)</label>
        </div>
        <div class="form-group">
          <input type="checkbox" name="dir_scan" id="dir_scan">
          <label for="dir_scan">Activer le scan de dossiers</label>
        </div>
      </div>
      <div class="form-group">
        <label for="password">Tester la robustesse du mot de passe</label>
        <input type="password" name="password" id="password" placeholder="Entrez un mot de passe">
      </div>
      <button type="submit">Scanner</button>
    </form>
  </div>
  <div id="loading"><p>Chargement...</p></div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(HOME_PAGE)

@app.route('/scan', methods=['POST'])
def scan():
    address = request.form.get('address', '')
    port_range = request.form.get('port_range', '1-1024')  # Plage par défaut si non fournie
    results = []
    error_count = 0

    # Ne scanner que si une adresse est fournie
    if address:
        if 'ping' in request.form:
            results.append(ping(address))
        if 'resolve_dns' in request.form:
            results.append(resolve_dns(address))
        if 'whois' in request.form:
            results.append(whois_lookup(address))
        if 'port_scan' in request.form:
            results.extend(scan_ports(address, port_range))
        if 'service_scan' in request.form:
            results.append(scan_services(address))
        if 'tcp_scan' in request.form:
            results.append(scan_tcp(address))
        if 'udp_scan' in request.form:
            results.append(scan_udp(address))
        if 'ping_sweep' in request.form:
            results.append(ping_sweep(address))
        if 'vuln_scan' in request.form:
            results.append(scan_vulnerabilities(address, port_range))
        if 'dir_scan' in request.form:
            file = request.files.get('dir_file')
            if file:
                found_directories, errors = dirbuster(file, address)
            else:
                dir_list_url = "https://raw.githubusercontent.com/digination/dirbuster-ng/master/wordlists/common.txt"
                found_directories, errors = dirbuster_with_url(dir_list_url, address)
            results.extend(found_directories)
            error_count += errors

    # Toujours tester le mot de passe s'il est fourni
    if 'password' in request.form:
        password = request.form['password']
        results.append(test_password_strength(password))

    results_html = '<br>'.join(results)
    session['results_html'] = results_html  # Stocker les résultats dans la session
    return render_template('scan_results.html', address=address, results_html=results_html, error_count=error_count)
@app.route('/download_pdf')
  def download_pdf():
    results_html = session.get('results_html', '')
    pdf = render_pdf(results_html)
    return send_file(pdf, attachment_filename='scan_results.pdf', as_attachment=True)

def render_pdf(html_content):
    result = BytesIO()
    pisa.CreatePDF(BytesIO(html_content.encode('utf-8')), dest=result)
    result.seek(0)
    return result

def ping(address):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        output = subprocess.check_output(["ping", param, "4", address], universal_newlines=True)
        return f"Ping réussi pour {address}:\n{output}"
    except subprocess.CalledProcessError as e:
        return f"Ping échoué pour {address}: {e}"

def resolve_dns(address):
    try:
        ip = socket.gethostbyname(address)
        return f"Résolution DNS pour {address}: {ip}"
    except socket.gaierror:
        return f"Impossible de résoudre {address}"

def whois_lookup(address):
    try:
        w = whois.whois(address)
        return f"Whois pour {address}:\n{w}"
    except Exception as e:
        return f"Whois échoué pour {address}: {e}"

def scan_ports(address, port_range):
    nm = nmap.PortScanner()
    nm.scan(address, port_range)
    results = []
    for host in nm.all_hosts():
        results.append(f"Scan de ports pour {host}:")
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                results.append(f"Port : {port}\tEtat : {nm[host][proto][port]['state']}")
    return '\n'.join(results)  # Convertir la liste en une seule chaîne de caractères

def scan_services(address):
    nm = nmap.PortScanner()
    nm.scan(address, arguments='-sV')
    results = []
    for host in nm.all_hosts():
        results.append(f"Scan des services pour {host}:")
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                service = str(nm[host][proto][port].get('product', 'Unknown'))
                version = str(nm[host][proto][port].get('version', ''))
                results.append(f"Port : {port}\tService : {service}\tVersion : {version}")
    return '\n'.join(results)  # Convertir la liste en une seule chaîne de caractères

def scan_tcp(address):
    nm = nmap.PortScanner()
    nm.scan(address, arguments='-sT')
    results = []
    for host in nm.all_hosts():
        results.append(f"Scan TCP pour {host}:")
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = str(nm[host][proto][port]['state'])  # Convertir l'état en chaîne de caractères
                results.append(f"Port : {port}\tEtat : {state}")
    return '\n'.join(results)  # Convertir la liste en une seule chaîne de caractères avec des sauts de ligne

def scan_udp(address):
    nm = nmap.PortScanner()
    nm.scan(address, arguments='-sP')  # Utiliser -sP pour un scan ping sans privilèges root
    results = []
    for host in nm.all_hosts():
        results.append(f"Scan UDP pour {host}:")
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = str(nm[host][proto][port]['state'])  # Convertir l'état en chaîne de caractères
                results.append(f"Port : {port}\tEtat : {state}")
    return '\n'.join(results)  # Convertir la liste en une seule chaîne de caractères avec des sauts de ligne

def ping_sweep(address):
    nm = nmap.PortScanner()
    nm.scan(hosts=address, arguments='-sn')
    results = []
    for host in nm.all_hosts():
        results.append(f"Balayage Ping pour {host} : {nm[host].state()}")
    return '\n'.join(results)  # Convertir la liste en une seule chaîne de caractères avec des sauts de ligne

def scan_vulnerabilities(address, port_range):
    nm = nmap.PortScanner()
    nm.scan(address, port_range, arguments='--script vuln')
    results = []
    for host in nm.all_hosts():
        results.append(f"Scan de vulnérabilités pour {host}:")
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if 'script' in nm[host][proto][port] and 'vuln' in nm[host][proto][port]['script']:
                    vulns = ', '.join(nm[host][proto][port]['script']['vuln'])  # Convertir la liste de vulnérabilités en chaîne de caractères
                    results.append(f"Port : {port}\tVulnérabilités : {vulns}")
    return '\n'.join(results)  # Convertir la liste en une seule chaîne de caractères avec des sauts de ligne

def dirbuster(file, target_url):
    directories = file.read().decode('utf-8').splitlines()
    return scan_directories(directories, target_url)

def dirbuster_with_url(url, target_url):
    response = requests.get(url)
    directories = response.text.splitlines()
    return scan_directories(directories, target_url)

def scan_directories(directories, url):
    found_directories = []
    error_count = 0
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
    }
    for directory in directories:
        full_url = f"{url}/{directory}"
        try:
            response = requests.get(full_url, headers=headers, timeout=10, allow_redirects=True, verify=True)
            status_code = response.status_code
            if status_code == 200:
                if not is_error_page(response.text):
                    found_directories.append(f"Trouvé: {full_url} (Code {status_code})")
                else:
                    found_directories.append(f"Trouvé !: {full_url} (Code {status_code})")
            elif status_code == 302:
                found_directories.append(f"Redirection: {full_url} (Code {status_code})")
            elif status_code == 404:
                found_directories.append(f"Non trouvé: {full_url} (Code {status_code})")
            elif status_code == 403:
                found_directories.append(f"Accès refusé: {full_url} (Code {status_code})")
            else:
                error_count += 1
                found_directories.append(f"Erreur inattendue pour {full_url} (Code {status_code})")
        except requests.RequestException as e:
            error_count += 1
            print(f"Erreur en accédant à {full_url}: {e}")
            found_directories.append(f"Erreur en accédant à {full_url}: {e}")
    return found_directories, error_count
def is_error_page(content):
    error_indicators = ["404 Not Found", "Error", "Not Found", "Erreur"]
    return any(indicator in content for indicator in error_indicators)

def test_password_strength(password):
    if not password:  # Vérifie si le mot de passe est vide
        return "Le champ de mot de passe est vide. Veuillez entrer un mot de passe."

    score = 0
    feedback = []

    if len(password) > 10:
        score += 25
    else:
        feedback.append("La longueur doit être supérieure à 10 caractères.")

    if re.search(r'[A-Z]', password):
        score += 25
    else:
        feedback.append("Le mot de passe doit contenir au moins une majuscule.")

    if re.search(r'[a-z]', password):
        score += 10  # Bonus for having at least one lowercase letter

    if re.search(r'[0-9]', password):
        score += 25
    else:
        feedback.append("Le mot de passe doit contenir au moins un chiffre.")

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 25
    else:
        feedback.append("Le mot de passe doit contenir au moins un caractère spécial.")

    return f"Robustesse du mot de passe: {score}/100. Suggestions: {', '.join(feedback)}"

if __name__ == '__main__':
    app.run(debug=True)