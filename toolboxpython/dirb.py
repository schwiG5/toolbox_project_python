import requests
import argparse

def load_directories(file_path):
    """Charge la liste des répertoires à partir d'un fichier texte."""
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def scan_directories(base_url, directories):
    """Scan les répertoires pour voir s'ils existent sur le serveur web."""
    found_directories = []
    for directory in directories:
        url = f"{base_url}/{directory}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                found_directories.append(url)
                print(f"Trouvé: {url}")
            else:
                print(f"Non trouvé ({response.status_code}): {url}")
        except requests.RequestException as e:
            print(f"Erreur lors de l'accès à {url}: {e}")
    return found_directories

def main():
    parser = argparse.ArgumentParser(description="Simple DirBuster Script")
    parser.add_argument('base_url', help="L'URL de base du site à scanner. Exemple: https://example.com")
    parser.add_argument('file_path', help="Chemin du fichier contenant les répertoires à tester.")
    args = parser.parse_args()

    directories = load_directories(args.file_path)
    if not directories:
        print("Le fichier fourni est vide ou n'existe pas.")
        return

    print(f"Démarrage du scan pour {args.base_url}")
    found = scan_directories(args.base_url, directories)
    print(f"Scan terminé. {len(found)} répertoires trouvés sur {len(directories)} testés.")

if __name__ == "__main__":
    main()
