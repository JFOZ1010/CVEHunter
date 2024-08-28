import requests
import time
import lzma
import json
import os

from datetime import datetime, timezone
from dotenv import load_dotenv
from pathlib import Path
#from datetime import timedelta


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')


# URL base de GitHub Releases
BASE_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/download/v2024.08.28-000008/"
API_KEY = os.getenv('API_KEY_NVD')  # Si necesitas usar una API key

def fetch_cves():
    cve_list = []
    years = range(2018, 2025)  # Años de interés desde 2018 hasta 2024

    for year in years:
        # Construimos la URL para el archivo correspondiente al año
        file_url = f"{BASE_URL}CVE-{year}.json.xz"
        file_name = f"CVE-{year}.json.xz"
        
        try:
            # Descargamos el archivo
            response = requests.get(file_url, headers={'Authorization': f'apiKey {API_KEY}'})
            response.raise_for_status()

            # Guardamos el archivo en el sistema
            with open(file_name, 'wb') as file:
                file.write(response.content)
            
            # Descomprimimos el archivo
            with lzma.open(file_name, 'rt') as lzma_file:
                cve_data = json.load(lzma_file)
            
            # Verificamos si la clave 'cve_items' existe en el JSON
            if 'cve_items' not in cve_data:
                print(f"La clave 'cve_items' no está presente en el archivo {file_name}.")
                continue
            
            # Procesamos los CVEs
            for item in cve_data['cve_items']:
                cve_id = item['id']
                published_date = item['published']
                descriptions = item['descriptions']
                description = next((desc['value'] for desc in descriptions if desc['lang'] == 'en'), 'No description available')

                # Extraemos la severidad de CVSS
                severity = None
                cvss_metrics_v3 = item.get('metrics', {}).get('cvssMetricV31', [])
                if cvss_metrics_v3:
                    severity = cvss_metrics_v3[0]['cvssData'].get('baseSeverity', 'MEDIUM')
                else:
                    cvss_metrics_v2 = item.get('metrics', {}).get('cvssMetricV2', [])
                    if cvss_metrics_v2:
                        severity = cvss_metrics_v2[0]['baseSeverity']
                
                cve_dict = {
                    'cve_id': cve_id,
                    'description': description,
                    'published_date': published_date,
                    'severity': severity,
                }
                cve_list.append(cve_dict)
            
            # Eliminamos el archivo descargado para liberar espacio
            os.remove(file_name)

        except requests.RequestException as e:
            print(f"Error al descargar o procesar el archivo {file_name}: {e}")
            continue

            # Guardamos los CVEs en un archivo .txt
    output_file = 'cves_data.txt'
    with open(output_file, 'w') as f:
        json.dump(cve_list, f, indent=4)

    print(f"CVEs guardados en {output_file}")

    return cve_list