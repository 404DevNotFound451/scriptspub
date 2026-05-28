# Compatibilite : Python 3.6+
# Teste sur : macOS, Rocky Linux 8
# Dependances externes : nmap (sudo apt/yum install nmap)
#
# Points de vigilance Python 3.6 :
#   - f-strings : OK (3.6+)
#   - subprocess.run : OK (3.5+), capture_output=True evite (3.7+ seulement)
#   - urllib.parse.quote : OK (3.x), NE PAS utiliser urllib.request.quote (inexistant)
#   - ThreadPoolExecutor : OK (3.2+)

import ipaddress
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET
import os
import tempfile
import urllib.request
import urllib.error
import urllib.parse
import time
import datetime

# ---------------------------------------------
# platform detecte une seule fois
# ---------------------------------------------
IS_WINDOWS = platform.system().lower() == "windows"


# =============================================
# BANNIERE DE DEMARRAGE
# =============================================

def afficher_banniere():
    """
    Banniere ASCII inspiree du logo darkproject : figure encapuchonnee.

    Structure de l'art ASCII :
      - Arc exterieur large  = contour arriere du hood
      - Arc interieur        = ouverture du visage (zone sombre)
      - | | central          = couture / zip avant du hoodie
      - Bas evasé            = epaules

    Pourquoi des print() separes ?
    Chaque backslash voulu dans la sortie s'ecrit \\ en Python.
    Ligne par ligne on repere les erreurs facilement.
    """
    print("=" * 52)
    print("")
    print("              ____________")
    print("            /              \\")
    print("           /   __________   \\")
    print("          /   /            \\   \\")
    print("         /   /              \\   \\")
    print("        /   /                \\   \\")
    print("       |   |                  |   |")
    print("       |   |                  |   |")
    print("        \\   \\                /   /")
    print("         \\   '-.._______..-'   /")
    print("          \\        |  |        /")
    print("           \\       |  |       /")
    print("        ____\\      |  |      /____")
    print("       /     '--.  |  |  .--'     \\")
    print("      /          '-|  |-'          \\")
    print("     /             |  |             \\")
    print("")
    print("          d a r k p r o j e c t")
    print("            from  PraxialCyber")
    print("")
    print("=" * 52)
    print("")


# =============================================
# INTERFACES RESEAU LOCALES
# =============================================

def get_local_ips():
    """
    Retourne la liste des IPs locales de la machine sous forme de strings.
    Tente 'ip a' en premier (Linux moderne), puis 'ifconfig' en fallback (macOS/ancien Linux).

    Parsing de 'ip a' :
      Les lignes qui nous interessent ressemblent a :
        inet 192.168.0.10/24 brd 192.168.0.255 scope global eth0
      On split par mots : parts[1] = IP/masque, parts[-1] = nom interface.

    Parsing de 'ifconfig' :
      Structure differente : le nom d'interface est sur sa propre ligne,
      l'IP est sur la ligne suivante avec 'inet'.
        eth0: flags=...
            inet 192.168.0.10  netmask ...
      On garde en memoire l'interface courante pour l'associer a l'IP.

    On ignore toujours 127.x.x.x (loopback).
    """
    ips = []

    # --- Tentative avec 'ip a' ---
    try:
        result = subprocess.run(
            ["ip", "a"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        if result.returncode == 0:
            output = result.stdout.decode("utf-8", errors="replace")
            for line in output.splitlines():
                line = line.strip()
                # On cherche les lignes IPv4 uniquement (pas inet6)
                if line.startswith("inet "):
                    parts = line.split()
                    # parts[1] = "192.168.0.10/24", parts[-1] = "eth0"
                    ip_cidr = parts[1]
                    iface   = parts[-1]
                    ip      = ip_cidr.split("/")[0]
                    if not ip.startswith("127."):
                        ips.append((iface, ip_cidr))
            if ips:
                return ips
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass  # 'ip' n'existe pas, on essaie ifconfig

    # --- Fallback sur 'ifconfig' ---
    try:
        result = subprocess.run(
            ["ifconfig"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        if result.returncode == 0:
            output = result.stdout.decode("utf-8", errors="replace")
            current_iface = "?"
            for line in output.splitlines():
                # Ligne d'interface : commence sans espace (Linux) ou avec le nom (macOS)
                if line and not line.startswith(" ") and not line.startswith("\t"):
                    # "eth0: flags=..." ou "eth0      Link encap:..."
                    current_iface = line.split(":")[0].split()[0]
                elif "inet " in line and "inet6" not in line:
                    parts = line.strip().split()
                    # Trouve 'inet' et prend le mot suivant
                    try:
                        idx = parts.index("inet")
                        ip  = parts[idx + 1]
                        # Sur macOS l'IP peut etre directement apres inet
                        # Sur Linux : "inet addr:192.168.x.x" (ancien ifconfig)
                        if ip.startswith("addr:"):
                            ip = ip[5:]
                        if not ip.startswith("127."):
                            ips.append((current_iface, ip))
                    except (ValueError, IndexError):
                        pass
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return ips


def afficher_ips_locales():
    """Affiche les IPs de la machine au demarrage."""
    ips = get_local_ips()
    print("[INFO] IP(s) de cette machine :")
    if ips:
        for iface, ip in ips:
            print(f"   {iface:<12} -> {ip}")
    else:
        print("   Impossible de determiner les IPs locales.")
    print()


# =============================================
# UTILITAIRES
# =============================================

def is_present(host):
    """Ping un hote pour savoir s'il repond. Retourne True/False."""
    param_count   = "-n" if IS_WINDOWS else "-c"
    param_timeout = "-w" if IS_WINDOWS else "-W"
    try:
        result = subprocess.run(
            ["ping", param_count, "1", param_timeout, "1", str(host)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def check_nmap_installed():
    """Verifie si nmap est disponible sur le systeme."""
    try:
        subprocess.run(["nmap", "--version"],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL,
                       timeout=3)
        return True
    except FileNotFoundError:
        return False


def lookup_mac_vendor(mac_addr):
    """
    Interroge l'API macvendors.com pour identifier le constructeur d'une carte reseau.

    L'OUI (Organizationally Unique Identifier) correspond aux 3 premiers octets
    de la MAC, attribues par l'IEEE a chaque fabricant.
    Ex : AA:BB:CC:DD:EE:FF -> OUI = AA:BB:CC

    Limitation : nmap ne remonte les MACs que pour les hotes sur le meme segment
    reseau local. Les hotes distants (routes) n'auront jamais de MAC.
    """
    if not mac_addr or mac_addr == "Non detectee":
        return "Inconnu"

    oui = mac_addr[:8]  # "AA:BB:CC:DD:EE:FF" -> "AA:BB:CC"
    url = f"https://api.macvendors.com/{urllib.parse.quote(oui)}"

    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            vendor = response.read().decode("utf-8").strip()
            return vendor if vendor else "Inconnu"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "Inconnu"
        return "Inconnu"
    except (urllib.error.URLError, Exception):
        return "Inconnu"


def cleanup_files(paths):
    """Supprime une liste de fichiers s'ils existent."""
    for path in paths:
        if path and os.path.exists(path):
            os.remove(path)
            print(f"[NETTOYAGE] Supprime : {path}")


# =============================================
# MENU DE SELECTION DU MODE DE SCAN
# =============================================

def menu_choix_scan():
    """
    Affiche le menu principal et retourne la liste d'IPs a scanner.

    Trois modes :
      1. IP unique      -> on cible directement une machine
      2. Plage IP       -> CIDR (ex: 192.168.0.0/24), ping scan puis nmap
      3. Plusieurs plages -> meme chose sur plusieurs reseaux
    """
    print("Que voulez-vous scanner ?")
    print("  1. Une IP unique")
    print("  2. Une plage d'IP  (ex: 192.168.0.0/24)")
    print("  3. Plusieurs plages d'IP")
    print()

    while True:
        choix = input("Votre choix (1/2/3) : ").strip()
        if choix in ['1', '2', '3']:
            break
        print("[ERREUR] Entrez 1, 2 ou 3.")

    if choix == '1':
        return collecter_ip_unique()
    elif choix == '2':
        return collecter_plage_unique()
    else:
        return collecter_plusieurs_plages()


def collecter_ip_unique():
    """Demande une IP unique et la retourne dans une liste."""
    while True:
        ip_str = input("Entrez l'IP a scanner (ex: 192.168.0.1) : ").strip()
        try:
            # On valide que c'est bien une IP
            ipaddress.ip_address(ip_str)
            return [ip_str]
        except ValueError:
            print(f"[ERREUR] '{ip_str}' n'est pas une adresse IP valide.")


def collecter_plage_unique():
    """Demande une plage CIDR et retourne les hotes actifs apres ping scan."""
    while True:
        plage = input("Entrez la plage (ex: 192.168.0.0/24) : ").strip()
        actifs = scan_with_ping(plage)
        if actifs is not None:
            return actifs


def collecter_plusieurs_plages():
    """Demande plusieurs plages et retourne tous les hotes actifs."""
    print("Entrez les plages une par une. Tapez 'fin' pour terminer.")
    all_actifs = []
    while True:
        plage = input("Plage (ou 'fin') : ").strip()
        if plage.lower() in ['fin', 'done', '', 'quit']:
            break
        if plage:
            actifs = scan_with_ping(plage)
            if actifs:
                all_actifs.extend(actifs)
    return all_actifs


# =============================================
# SCAN PING
# =============================================

def scan_with_ping(network_str):
    """
    Scanne un reseau entier avec des pings paralleles.
    Retourne la liste des IPs actives, ou None si le reseau est invalide.
    """
    try:
        network = ipaddress.ip_network(network_str, strict=False)
    except ValueError as e:
        print(f"[ERREUR] Reseau invalide : {e}")
        return None

    hosts = list(network.hosts())
    active_hosts = []

    print(f"\n[SCAN] Ping en cours sur {network} ({len(hosts)} hotes)...")

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(is_present, hosts)
        for host, is_active in zip(hosts, results):
            if is_active:
                active_hosts.append(str(host))

    print(f"   -> {len(active_hosts)} hotes UP trouves.")
    return active_hosts


def save_ping_results_to_xml(active_hosts):
    """
    Sauvegarde les hotes actifs dans un fichier XML intermediaire.
    Ce fichier est nettoye a la fin du programme.

    Retourne le chemin du fichier cree.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, "hosts_ping.xml")

    root = ET.Element("hosts")
    for ip in active_hosts:
        host_elem = ET.SubElement(root, "host")
        ET.SubElement(host_elem, "ip").text = ip
        ET.SubElement(host_elem, "method").text = "ping"

    tree = ET.ElementTree(root)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)
    print(f"[OK] Hotes actifs sauvegardes dans '{output_path}' (fichier temporaire)")
    return output_path


# =============================================
# SCAN NMAP
# =============================================

def scan_with_nmap_on_ips(active_ips):
    """
    Lance nmap sur la liste d'IPs et retourne le chemin du XML nmap genere.
    Retourne None si le scan est annule ou echoue.

    Sans -Pn : nmap fait sa propre decouverte ARP -> remonte les adresses MAC
               pour les hotes sur le meme segment reseau local.
               Necessite sudo pour les raw sockets ARP.
    """
    if not active_ips:
        return None

    print(f"\nLancement de Nmap sur {len(active_ips)} IP(s) actives...")

    confirm = input("Continuer avec Nmap ? (o/n) : ").strip().lower()
    if confirm not in ['o', 'oui', 'y', 'yes']:
        print("Nmap annule.")
        return None

    # Fichier temporaire : liste des IPs a passer a nmap (-iL)
    tmp_ips_path = None
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
        for ip in active_ips:
            tmp.write(ip + '\n')
        tmp_ips_path = tmp.name

    # Fichier temporaire : XML brut genere par nmap
    tmp_xml_path = tempfile.mktemp(suffix=".xml")

    try:
        cmd = ["nmap", "-T4", "--open", "-sV", "-oX", tmp_xml_path, "-iL", tmp_ips_path]
        print("ça peut être long ! on va prendre un café ? :)")
        subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=900
        )

        if os.path.exists(tmp_xml_path):
            print("[OK] Scan Nmap termine")
            return tmp_xml_path, tmp_ips_path
        else:
            print("[ERREUR] Nmap n'a pas produit de fichier XML.")
            cleanup_files([tmp_ips_path])
            return None, tmp_ips_path

    except Exception as e:
        print(f"[ERREUR] Nmap : {e}")
        cleanup_files([tmp_ips_path])
        return None, tmp_ips_path


# =============================================
# AFFICHAGE ET SAUVEGARDE DES RESULTATS
# =============================================

def parse_and_save_results(xml_file):
    """
    Parse le XML Nmap, affiche les resultats a l'ecran,
    et sauvegarde les resultats dans un fichier XML final horodate.

    Le fichier final est le seul qui reste apres nettoyage.
    Format du nom : scan_YYYYMMDD_HHMMSS.xml
    """
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        print(f"\n{'='*70}")
        print("RESULTATS DETAILLES DU SCAN NMAP")
        print(f"{'='*70}\n")

        hosts = root.findall("host")

        # --- Preparation du XML de resultats final ---
        now = datetime.datetime.now()
        result_root = ET.Element("scan")
        result_root.set("date", now.strftime("%Y-%m-%d"))
        result_root.set("time", now.strftime("%H:%M:%S"))
        result_root.set("total_hosts", str(len(hosts)))

        for idx, host in enumerate(hosts, start=1):

            # Adresse IP
            ip_elem = host.find(".//address[@addrtype='ipv4']")
            ip_addr = ip_elem.get("addr") if ip_elem is not None else "Inconnue"

            # Adresse MAC -- presente uniquement pour les hotes sur le meme segment local
            mac_elem = host.find(".//address[@addrtype='mac']")
            mac_addr = mac_elem.get("addr") if mac_elem is not None else "Non detectee"

            # Constructeur
            if mac_elem is not None:
                nmap_vendor = mac_elem.get("vendor", "").strip()
                if nmap_vendor:
                    vendor = nmap_vendor
                else:
                    print(f"   [LOOKUP] Constructeur pour {mac_addr}...")
                    vendor = lookup_mac_vendor(mac_addr)
                    if idx < len(hosts):
                        time.sleep(1)  # rate limit API : 1 req/sec
            else:
                vendor = "Inconnu"

            # Affichage ecran
            print(f"[+] Hote        : {ip_addr}")
            print(f"    MAC          : {mac_addr}")
            print(f"    Constructeur : {vendor}")

            # Ports ouverts -- filtre manuel : 'state' est un element enfant de <port>
            all_ports = host.findall(".//port")
            open_ports = [
                p for p in all_ports
                if p.find("state") is not None
                and p.find("state").get("state") == "open"
            ]

            if open_ports:
                print("    Ports ouverts :")
            else:
                print("    Aucun port ouvert detecte.")

            # --- Construction du noeud XML pour cet hote ---
            host_elem = ET.SubElement(result_root, "host")
            host_elem.set("ip", ip_addr)
            host_elem.set("mac", mac_addr)
            host_elem.set("vendor", vendor)

            for port in open_ports:
                portid   = port.get("portid")
                protocol = port.get("protocol")
                service  = port.find("service")

                service_name = service.get("name", "unknown") if service is not None else "unknown"
                product      = service.get("product", "")     if service is not None else ""
                version      = service.get("version", "")     if service is not None else ""

                version_parts = " ".join(filter(None, [product, version]))
                version_info  = f"({version_parts})" if version_parts else ""

                print(f"      {portid:>5}/{protocol} -> {service_name:<12} {version_info}")

                # Noeud port dans le XML final
                port_elem = ET.SubElement(host_elem, "port")
                port_elem.set("id", portid)
                port_elem.set("protocol", protocol)
                port_elem.set("service", service_name)
                port_elem.set("product", product)
                port_elem.set("version", version)

            print("-" * 60)

        # --- Sauvegarde du XML final ---
        script_dir = os.path.dirname(os.path.abspath(__file__))
        filename = "scan_{}.xml".format(now.strftime("%Y%m%d_%H%M%S"))
        result_path = os.path.join(script_dir, filename)

        result_tree = ET.ElementTree(result_root)
        result_tree.write(result_path, encoding="utf-8", xml_declaration=True)
        print(f"\n[OK] Resultats sauvegardes dans '{result_path}'")
        return result_path

    except Exception as e:
        print(f"[ERREUR] Lecture du fichier XML : {e}")
        return None


# =============================================
# POINT D'ENTREE
# =============================================

def main():
    afficher_banniere()

    # --- Affichage des IPs locales ---
    afficher_ips_locales()

    # Suivi des fichiers a nettoyer en fin de programme
    fichiers_a_nettoyer = []

    # --- Choix du mode de scan ---
    active_ips = menu_choix_scan()

    if not active_ips:
        print("Aucun hote a scanner.")
        return

    active_ips = sorted(set(active_ips))

    print(f"\n{'='*60}")
    print(f"{len(active_ips)} hote(s) a scanner")
    print(f"{'='*60}\n")
    for ip in active_ips:
        print(f"[UP] {ip}")

    # --- Sauvegarde ping intermediaire (sera nettoyee) ---
    # On ne sauvegarde pas si on a scanne une IP unique (pas de ping scan)
    if len(active_ips) > 1:
        ping_xml = save_ping_results_to_xml(active_ips)
        fichiers_a_nettoyer.append(ping_xml)

    # --- Scan Nmap ---
    if not check_nmap_installed():
        print("\n[INFO] Nmap n'est pas installe -> sudo apt/yum install nmap")
        cleanup_files(fichiers_a_nettoyer)
        return

    print("\n[INFO] Pour detecter les adresses MAC, lancez le script avec sudo.")
    nmap_result = scan_with_nmap_on_ips(active_ips)

    # scan_with_nmap_on_ips retourne un tuple (xml_path, tmp_ips_path)
    if nmap_result is None:
        cleanup_files(fichiers_a_nettoyer)
        return

    tmp_xml, tmp_ips = nmap_result
    fichiers_a_nettoyer.append(tmp_ips)  # liste IPs temp pour nmap

    # --- Affichage et sauvegarde des resultats ---
    if tmp_xml:
        parse_and_save_results(tmp_xml)
        fichiers_a_nettoyer.append(tmp_xml)  # XML brut nmap, plus utile apres parsing

    # --- Nettoyage final ---
    print(f"\n{'='*60}")
    cleanup_files(fichiers_a_nettoyer)

    print("\nProgramme termine.")


if __name__ == "__main__":
    main()
