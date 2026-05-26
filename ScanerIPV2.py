import ipaddress
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET
import os
import tempfile
import urllib.request
import urllib.error
import time


# ---------------------------------------------
# platform detecte une seule fois
# ---------------------------------------------
IS_WINDOWS = platform.system().lower() == "windows"


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

    Comment ca marche :
    Chaque fabricant de carte reseau recoit de l'IEEE un OUI (Organizationally Unique
    Identifier) : les 3 premiers octets de l'adresse MAC. Les 3 suivants sont libres.
    Ex : AA:BB:CC:DD:EE:FF -> OUI = AA:BB:CC -> on envoie ca a l'API.

    Limitation : nmap ne remonte les MACs que pour les hotes sur le meme segment reseau
    local (meme broadcast domain). Les hotes distants (routes) n'auront jamais de MAC.

    Retourne le nom du constructeur, ou "Inconnu" si OUI non trouve dans la base.
    """
    if not mac_addr or mac_addr == "Non detectee":
        return "Inconnu"

    oui = mac_addr[:8]  # "AA:BB:CC:DD:EE:FF" -> "AA:BB:CC"
    url = f"https://api.macvendors.com/{urllib.request.quote(oui)}"

    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            vendor = response.read().decode("utf-8").strip()
            return vendor if vendor else "Inconnu"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "Inconnu"  # OUI inconnu dans la base, pas une erreur reseau
        return "Inconnu"
    except (urllib.error.URLError, Exception):
        return "Inconnu"


def scan_with_ping(network_str):
    """Scanne un reseau entier avec des pings paralleles."""
    try:
        network = ipaddress.ip_network(network_str, strict=False)
    except ValueError as e:
        print(f"[ERREUR] Reseau invalide : {e}")
        return []

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


def scan_with_nmap_on_ips(active_ips):
    """Lance nmap sur la liste d'IPs actives et affiche les resultats."""
    if not active_ips:
        return []

    print(f"\nLancement de Nmap sur {len(active_ips)} IP(s) actives...")

    confirm = input("Continuer avec Nmap ? (o/n) : ").strip().lower()
    if confirm not in ['o', 'oui', 'y', 'yes']:
        print("Nmap annule.")
        return active_ips

    # Fichier temporaire avec la liste des IPs a scanner
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
        for ip in active_ips:
            tmp.write(ip + '\n')
        tmp_path = tmp.name

    output_xml = tempfile.mktemp(suffix=".xml")

    try:
        # -T4    = vitesse agressive
        # --open = affiche seulement les ports ouverts
        # -sV    = detection de version des services
        # -oX    = export XML
        # Sans -Pn : nmap fait sa propre decouverte ARP -> remonte les adresses MAC
        #            pour les hotes sur le meme segment reseau local.
        #            Necessite sudo pour les raw sockets ARP.
        cmd = ["nmap", "-T4", "--open", "-sV", "-oX", output_xml, "-iL", tmp_path]
        print("Nmap en cours... (decouverte ARP activee, peut etre plus long)")
        subprocess.run(cmd, capture_output=True, timeout=900)

        if os.path.exists(output_xml):
            print("[OK] Scan Nmap termine")
            parse_and_display_nmap_results(output_xml)
    except Exception as e:
        print(f"[ERREUR] Nmap : {e}")
    finally:
        for f in [tmp_path, output_xml]:
            if os.path.exists(f):
                os.remove(f)

    return active_ips


def parse_and_display_nmap_results(xml_file):
    """Parse le XML Nmap et affiche les informations de facon claire.
    Pour chaque hote : IP, MAC + constructeur (si disponible), ports ouverts.
    """
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        print(f"\n{'='*70}")
        print("RESULTATS DETAILLES DU SCAN NMAP")
        print(f"{'='*70}\n")

        hosts = root.findall("host")

        for idx, host in enumerate(hosts, start=1):

            # Adresse IP
            ip_elem = host.find(".//address[@addrtype='ipv4']")
            ip_addr = ip_elem.get("addr") if ip_elem is not None else "Inconnue"

            # Adresse MAC -- presente uniquement pour les hotes sur le meme segment local
            mac_elem = host.find(".//address[@addrtype='mac']")
            mac_addr = mac_elem.get("addr") if mac_elem is not None else "Non detectee"

            # Constructeur : nmap peut le fournir directement dans le XML.
            # Sinon on appelle l'API macvendors.com avec l'OUI (3 premiers octets).
            if mac_elem is not None:
                nmap_vendor = mac_elem.get("vendor", "").strip()
                if nmap_vendor:
                    vendor = nmap_vendor  # nmap l'a trouve, pas besoin d'appel API
                else:
                    print(f"   [LOOKUP] Constructeur pour {mac_addr}...")
                    vendor = lookup_mac_vendor(mac_addr)
                    # L'API gratuite macvendors.com est limitee a 1 req/sec
                    if idx < len(hosts):
                        time.sleep(1)
            else:
                vendor = "Inconnu"

            print(f"[+] Hote        : {ip_addr}")
            print(f"    MAC          : {mac_addr}")
            print(f"    Constructeur : {vendor}")

            # Ports ouverts -- filtre manuel car 'state' est un element enfant de <port>,
            # pas un attribut. Le XPath port[@state='open'] ne fonctionne pas ici.
            all_ports = host.findall(".//port")
            open_ports = [
                p for p in all_ports
                if p.find("state") is not None
                and p.find("state").get("state") == "open"
            ]

            if open_ports:
                print("    Ports ouverts :")
                for port in open_ports:
                    portid   = port.get("portid")
                    protocol = port.get("protocol")
                    service  = port.find("service")

                    service_name = service.get("name", "unknown") if service is not None else "unknown"
                    product      = service.get("product", "")      if service is not None else ""
                    version      = service.get("version", "")      if service is not None else ""

                    version_parts = " ".join(filter(None, [product, version]))
                    version_info  = f"({version_parts})" if version_parts else ""

                    print(f"      {portid:>5}/{protocol} -> {service_name:<12} {version_info}")
            else:
                print("    Aucun port ouvert detecte.")

            print("-" * 60)

    except Exception as e:
        print(f"[ERREUR] Lecture du fichier XML : {e}")


def save_ping_results_to_xml(active_hosts):
    """Sauvegarde les hotes actifs dans un fichier XML.

    Le fichier est cree dans le meme dossier que ce script,
    peu importe depuis quel repertoire on le lance.
    os.path.abspath(__file__) -> chemin absolu du script
    os.path.dirname(...)      -> dossier qui le contient
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
    print(f"[OK] Resultats ping sauvegardes dans '{output_path}'")


def main():
    print("=== Scanner Ping + Nmap Avance V2 ===\n")

    networks_to_scan = []
    while True:
        user_input = input("Entrez un reseau (ex: 192.168.0.0/24) ou 'fin' : ").strip()
        if user_input.lower() in ['fin', 'done', '', 'quit']:
            break
        if user_input:
            networks_to_scan.append(user_input)

    if not networks_to_scan:
        print("Aucun reseau saisi.")
        return

    all_active_hosts = []
    for network_str in networks_to_scan:
        active = scan_with_ping(network_str)
        all_active_hosts.extend(active)

    if not all_active_hosts:
        print("Aucun hote actif trouve.")
        return

    all_active_hosts = sorted(set(all_active_hosts))

    print(f"\n{'='*60}")
    print(f"{len(all_active_hosts)} hotes UP trouves au total")
    print(f"{'='*60}\n")

    for ip in all_active_hosts:
        print(f"[UP] {ip}")

    save_ping_results_to_xml(all_active_hosts)

    if check_nmap_installed():
        print("\n[INFO] Pour detecter les adresses MAC, lancez le script avec sudo.")
        scan_with_nmap_on_ips(all_active_hosts)
    else:
        print("\n[INFO] Nmap n'est pas installe -> sudo apt install nmap")

    print("\nProgramme termine.")


if __name__ == "__main__":
    main()
