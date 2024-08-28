import requests
import lzma
import json
import os
from datetime import datetime 

#from django.core.exceptions import ObjectDoesNotExist
from .models import CVE
from django.utils.dateparse import parse_datetime


# URL base de GitHub Releases
BASE_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/download/v2024.08.28-000008/"
RECENT_CVES_URL = f"{BASE_URL}CVE-recent.json.xz"

def format_date(date_str):
    """Convierte la fecha al formato YYYY-MM-DD si es posible."""
    try:
        # Intentar parsear la fecha y convertirla al formato requerido
        date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return date_obj.strftime('%Y-%m-%d')
    except ValueError:
        # Si la fecha no se puede convertir, devolver el valor original
        return date_str

def fetch_recent_cves():
    temp_file_name = 'CVE-recent.json.xz'

    try:
        # Descargar el archivo de CVEs recientes
        response = requests.get(RECENT_CVES_URL)
        response.raise_for_status()

        # Guardar el archivo descargado temporalmente
        with open(temp_file_name, 'wb') as temp_file:
            temp_file.write(response.content)

        # Descomprimir y leer el archivo
        with lzma.open(temp_file_name, 'rt') as lzma_file:
            recent_cve_data = json.load(lzma_file)
            recent_cve_items = recent_cve_data.get('cve_items', [])

        # Definir el rango de fechas para filtrar CVEs
        start_date = datetime(2023, 1, 1)  # Fecha de inicio del rango
        end_date = datetime(2024, 12, 31)  # Fecha de fin del rango

        cve_list = []
        for item in recent_cve_items:
            cve_id = item['id']
            description = next((desc['value'] for desc in item.get('descriptions', []) if desc['lang'] == 'en'), 'No description available')
            published_date = item.get('published', 'No date available')

            # Convertir la fecha a formato YYYY-MM-DD
            published_date = format_date(published_date)

            # Filtrar CVEs por el rango de fechas
            published_date_obj = parse_datetime(published_date)
            if not published_date_obj:
                continue
            if start_date <= published_date_obj <= end_date:
                # Extraer severidad de CVSS
                severity = 'MEDIUM'  # Valor predeterminado o basado en tus datos
                metrics = item.get('metrics', {})
                cvss_metrics_v3 = metrics.get('cvssMetricV31', [])
                if cvss_metrics_v3:
                    severity = cvss_metrics_v3[0]['cvssData'].get('baseSeverity', 'MEDIUM')
                else:
                    cvss_metrics_v2 = metrics.get('cvssMetricV2', [])
                    if cvss_metrics_v2:
                        severity = cvss_metrics_v2[0].get('baseSeverity', 'MEDIUM')

                cve_dict = {
                    'cve_id': cve_id,
                    'description': description,
                    'published_date': published_date,
                    'severity': severity,
                }
                cve_list.append(cve_dict)

        # Guardar o actualizar los CVEs en la base de datos
        for cve in cve_list:
            obj, created = CVE.objects.update_or_create(
                cve_id=cve['cve_id'],
                defaults={
                    'description': cve['description'],
                    'published_date': cve['published_date'],
                    'severity': cve['severity'],
                }
            )
            if created:
                print(f"Creado nuevo CVE: {cve['cve_id']}")
            else:
                print(f"Actualizado CVE: {cve['cve_id']}")

        os.remove(temp_file_name)
        print("CVEs actualizados en la base de datos.")

    except requests.RequestException as e:
        print(f"Error al descargar o procesar el archivo: {e}")

    except json.JSONDecodeError as e:
        print(f"Error al decodificar el archivo JSON: {e}")

    except Exception as e:
        print(f"Error inesperado: {e}")

# Llamada a la función para ejecutar el proceso
fetch_recent_cves()