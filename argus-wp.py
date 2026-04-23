#!/usr/bin/env python3
import os
import json
import requests
import argparse
import sys
import re
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

init(autoreset=True)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Argus-WP/1.0"
}

def print_info(msg): print(f"{Fore.CYAN}[*] {msg}{Style.RESET_ALL}")
def print_success(msg): print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")
def print_error(msg): print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")
def print_warning(msg): print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

def check_wordpress(url):
    print_info(f"Analizando el objetivo: {url}")
    is_wp = False
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        html = response.text
        if '/wp-content/' in html or '/wp-includes/' in html: is_wp = True
        if 'name="generator" content="WordPress' in html: is_wp = True
        license_resp = requests.get(f"{url}/license.txt", headers=HEADERS, timeout=5)
        if license_resp.status_code == 200 and 'WordPress' in license_resp.text: is_wp = True

        if is_wp:
            print_success("¡Objetivo confirmado! El sitio utiliza WordPress.")
            return True, html 
        else:
            print_error("No se han encontrado evidencias de WordPress.")
            return False, None
    except Exception as e:
        print_error(f"Error de conexión: {e}")
        sys.exit(1)

def enumerate_plugins_themes(html):
    print_info("Iniciando escaneo pasivo de plugins y temas...")
    soup = BeautifulSoup(html, 'html.parser')
    plugins = {} # Ahora es un diccionario {nombre: versión}
    theme = None
    tags = soup.find_all(['link', 'script'])
    
    for tag in tags:
        src = tag.get('href') or tag.get('src')
        if not src: continue
        
        # Buscar plugins y su versión si existe (?ver=X.X.X)
        plugin_match = re.search(r'/wp-content/plugins/([^/]+)/.*?(?:\?ver=([a-zA-Z0-9\.-]+))?', src)
        if plugin_match:
            plugin_name = plugin_match.group(1)
            version = plugin_match.group(2) if plugin_match.group(2) else "Desconocida"
            if plugin_name not in plugins or plugins[plugin_name] == "Desconocida":
                plugins[plugin_name] = version

        if not theme:
            theme_match = re.search(r'/wp-content/themes/([^/]+)/', src)
            if theme_match: theme = theme_match.group(1)

    if plugins:
        print_success(f"Se han encontrado {len(plugins)} plugin(s) expuesto(s).")
        for p_name, p_ver in plugins.items():
            print(f"    - {Fore.YELLOW}Plugin:{Style.RESET_ALL} {p_name} | {Fore.YELLOW}Versión:{Style.RESET_ALL} {p_ver}")
    if theme:
        print_success(f"Tema activo detectado: {theme}")
    return plugins, theme

def enumerate_users(url):
    print_info("Iniciando enumeración de usuarios vía REST API...")
    endpoint = f"{url}/wp-json/wp/v2/users"
    try:
        response = requests.get(endpoint, headers=HEADERS, timeout=10)
        
        # Validamos si la respuesta es exitosa
        if response.status_code == 200:
            try:
                users_data = response.json()
            except ValueError:
                print_error("El endpoint devolvió código 200 pero no contiene un JSON válido.")
                return []

            if not users_data:
                print_warning("El endpoint de usuarios está habilitado pero no devolvió resultados.")
                return []
            
            users = []
            print_success(f"¡Vulnerabilidad de Information Disclosure detectada! Se obtuvieron {len(users_data)} usuario(s):")
            for user in users_data:
                user_name = user.get('name', 'Desconocido')
                user_slug = user.get('slug', 'Desconocido')
                users.append({'name': user_name, 'slug': user_slug})
                print(f"    - {Fore.YELLOW}Usuario:{Style.RESET_ALL} {user_name} | {Fore.YELLOW}Slug:{Style.RESET_ALL} {user_slug}")
            return users
            
        elif response.status_code in [401, 403]:
            print_warning(f"El endpoint de usuarios está protegido/bloqueado (HTTP {response.status_code}).")
            return []
        else:
            print_error(f"El endpoint de usuarios devolvió un estado inesperado: HTTP {response.status_code}.")
            return []
            
    except Exception as e:
        print_error(f"Error al intentar conectar con la API REST: {e}")
        return []

def update_wordfence_db(force_update=False):
    db_dir = "db"
    db_file = os.path.join(db_dir, "wordfence_vulndb.json")
    url = "https://raw.githubusercontent.com/httpbnry/argus-wp/main/vulndb.json"
    
    # Crear directorio si no existe
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)
    
    if os.path.exists(db_file) and not force_update:
        print_info(f"Usando la base de datos local '{db_file}'.")
        return True

    print_info("Descargando la base de datos de vulnerabilidades (Mirror Argus-WP)...")
    try:
        response = requests.get(url, timeout=30)
        
        # Validar si HTTP es exitoso
        response.raise_for_status()
        
        with open(db_file, 'w', encoding='utf-8') as f:
            json.dump(response.json(), f)
        print_success(f"Base de datos actualizada exitosamente en '{db_file}'.")
        return True
            
    except requests.exceptions.RequestException as e:
        print_error(f"Error de red al intentar descargar la base de datos: {e}")
        return False
    except json.JSONDecodeError:
        print_error("El archivo descargado no es un JSON válido.")
        return False

def check_vulnerabilities_local(plugins):
    db_file = os.path.join("db", "wordfence_vulndb.json")
    found_vulns = {}
    
    if not os.path.exists(db_file):
        print_error("La BD local no existe. Ejecuta el script con --update-db.")
        return found_vulns

    print_info("Cruzando plugins detectados con la base de datos local de Wordfence...")
    try:
        with open(db_file, 'r', encoding='utf-8') as f:
            vuln_db = json.load(f)
            
        for plugin_name, version in plugins.items():
            clean_name = plugin_name.split('?')[0]
            if clean_name in vuln_db:
                vulns = vuln_db[clean_name].get("vulnerabilities", [])
                if vulns:
                    print(f"\n{Fore.RED}[!] ¡ALERTA CRÍTICA! Vulnerabilidades encontradas para: '{clean_name}'{Style.RESET_ALL}")
                    found_vulns[clean_name] = []
                    for vuln in vulns:
                        title = vuln.get("title", "Título no disponible")
                        cve = vuln.get("cve", "CVE no asignado")
                        cvss_score = vuln.get("cvss", {}).get("score", "N/A")
                        
                        found_vulns[clean_name].append({'title': title, 'cve': cve, 'cvss': cvss_score})
                        print(f"{Fore.RED}    - Título: {title}{Style.RESET_ALL}")
                        print(f"{Fore.RED}      [CVE: {cve}] | [CVSS: {cvss_score}]{Style.RESET_ALL}")
            else:
                print_success(f"Plugin '{clean_name}': No se encontraron vulnerabilidades críticas.")
                
    except json.JSONDecodeError:
        print_error(f"Error: El archivo '{db_file}' está corrupto.")
    except Exception as e:
        print_error(f"Error al procesar el JSON: {e}")
        
    return found_vulns

def brute_force_login(url, users):
    print_info("Iniciando módulo de fuerza bruta contra wp-login.php...")
    successful_logins = []
    
    if not users:
        print_warning("No hay usuarios descubiertos. Intentando con usuario por defecto: 'admin'")
        users = [{'name': 'admin', 'slug': 'admin'}]
        
    login_url = f"{url}/wp-login.php"
    
    # Top 20 Contraseñas
    passwords = [
        "123456", "123456789", "qwerty", "password", "1234567", "12345678", "12345", 
        "iloveyou", "111111", "123123", "admin", "admin123", "contraseña", "1234", 
        "letmein", "password123", "abc123", "qwertyuiop", "654321", "root"
    ]
    
    for user in users:
        username = user['slug']
        print_info(f"Atacando al usuario: {username}")
        
        for pwd in passwords:
            data = {'log': username, 'pwd': pwd, 'wp-submit': 'Log In'}
            try:
                # allow_redirects=False para interceptar la redirección tras un login exitoso
                response = requests.post(login_url, data=data, headers=HEADERS, timeout=5, allow_redirects=False)
                
                # Chequeamos si WordPress devuelve un código de redirección (302) y la cookie de logeo exitoso
                if response.status_code in [301, 302] and 'wordpress_logged_in_' in str(response.cookies):
                    print_success(f"¡ÉXITO CRÍTICO! Credenciales encontradas -> Usuario: {username} | Contraseña: {pwd}")
                    successful_logins.append({'username': username, 'password': pwd})
                    break
            except requests.exceptions.RequestException as e:
                print_error(f"Error de red durante fuerza bruta: {e}")
                break
                
    return successful_logins

def export_report(data, filename, fmt):
    try:
        if fmt == 'json':
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
        elif fmt == 'txt':
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=== Argus-WP Audit Report ===\n")
                f.write(f"URL Objetivo: {data.get('url')}\n")
                f.write(f"Tema Activo: {data.get('theme', 'No detectado')}\n\n")
                
                f.write("--- Plugins Detectados ---\n")
                for p, v in data.get('plugins', {}).items():
                    f.write(f"- {p} (Versión: {v})\n")
                
                f.write("\n--- Vulnerabilidades Críticas ---\n")
                vulns = data.get('vulnerabilities', {})
                if not vulns:
                    f.write("No se encontraron vulnerabilidades en la BD local.\n")
                for p, v_list in vulns.items():
                    f.write(f"[{p}]\n")
                    for v in v_list:
                        f.write(f"  - {v['title']} | {v['cve']} | CVSS: {v['cvss']}\n")
                        
                f.write("\n--- Usuarios Extraídos (API REST) ---\n")
                users = data.get('users', [])
                if not users:
                    f.write("Ninguno expuesto.\n")
                for u in users:
                    f.write(f"- {u['name']} (Slug: {u['slug']})\n")
                    
                f.write("\n--- Credenciales Compromisadas (Fuerza Bruta) ---\n")
                creds = data.get('brute_force_success', [])
                if not creds:
                    f.write("Ninguna o módulo no ejecutado.\n")
                for c in creds:
                    f.write(f"- {c['username']}:{c['password']}\n")
                    
        print_success(f"Reporte exportado exitosamente en '{filename}'.")
    except Exception as e:
        print_error(f"Error al exportar el reporte: {e}")

def check_url(url):
    """Verifica si la URL tiene http/https, intenta https primero, si falla intenta http."""
    if not url.startswith('http://') and not url.startswith('https://'):
        print_info(f"No se especificó protocolo, intentando con https://{url}")
        target = f"https://{url}"
        try:
            requests.get(target, headers=HEADERS, timeout=5)
            return target
        except requests.exceptions.RequestException:
            print_warning("Falló la conexión por HTTPS, intentando por HTTP...")
            target = f"http://{url}"
            return target
    return url

def main():
    parser = argparse.ArgumentParser(description="Argus-WP - Herramienta de auditoría para WordPress (TFG ASIR)")
    parser.add_argument("url", help="URL objetivo (ej. aclass.es o https://ejemplo.com)")
    parser.add_argument("-b", "--brute", action="store_true", help="Activar módulo de fuerza bruta para usuarios encontrados")
    parser.add_argument("--update-db", action="store_true", help="Fuerza la descarga/actualización de la base de datos de Wordfence (vía GitHub Mirror)")
    parser.add_argument("-o", "--output", help="Guardar el reporte de la auditoría en un archivo")
    parser.add_argument("-f", "--format", choices=['json', 'txt'], default='json', help="Formato del reporte (json o txt)")
    args = parser.parse_args()
    
    raw_url = args.url.rstrip('/') 
    
    banner = f"""{Fore.MAGENTA}
    ___                                     _       _____ 
   /   |  _________ ___  _______           | |     / /   |
  / /| | / ___/ __ `/ / / / ___/  ______   | | /| / / /| |
 / ___ |/ /  / /_/ / /_/ (__  )  /_____/   | |/ |/ / ___ |
/_/  |_/_/   \\__, /\\__,_/_____/            |__/|__/_/  |_|
            /____/                                        
{Fore.CYAN}       WordPress Audit Tool | By: httpbnry / jdb
{Style.RESET_ALL}"""
    print(banner)
    
    target_url = check_url(raw_url)
    
    # Inicializar el reporte
    report_data = {
        'url': target_url,
        'plugins': {},
        'theme': None,
        'vulnerabilities': {},
        'users': [],
        'brute_force_success': []
    }
    
    is_wp, html_content = check_wordpress(target_url)
    if not is_wp: sys.exit(0)
        
    plugins, theme = enumerate_plugins_themes(html_content)
    report_data['plugins'] = plugins
    report_data['theme'] = theme
    
    # Análisis de vulnerabilidades local (Wordfence)
    update_wordfence_db(force_update=args.update_db)
    vulns = check_vulnerabilities_local(plugins)
    report_data['vulnerabilities'] = vulns
    
    # Enumeración de usuarios
    users = enumerate_users(target_url)
    report_data['users'] = users
    
    # Módulo de fuerza bruta opcional
    if args.brute:
        creds = brute_force_login(target_url, users)
        report_data['brute_force_success'] = creds
        
    # Exportar reporte si se solicita
    if args.output:
        export_report(report_data, args.output, args.format)
    
    print(f"\n{Fore.MAGENTA}=== Auditoría Finalizada ==={Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
