from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from django.core.cache import cache


from .models import CVE, Vendor, Product
from .serializers import CVESerializer, VendorSerializer, ProductSerializer
from .cve_methods import scan_url, fetch_recent_cves

from pathlib import Path
import os
from dotenv import load_dotenv

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')



""" @api_view(['GET'])
def cve_list_view(request):
    cves = CVE.objects.all()
    serializer = CVESerializer(cves, many=True)
    return Response(serializer.data) """

@api_view(['GET'])
def cve_list_view(request):
    # Llamar a la función fetch_recent_cves para actualizar la base de datos
    fetch_recent_cves()
    
    # Obtener todos los CVEs actualizados
    cves = CVE.objects.all()
    serializer = CVESerializer(cves, many=True)
    
    return Response(serializer.data)
    

@api_view(['GET'])
def cve_detail_view(request, pk):
    try:
        cve = CVE.objects.get(pk=pk)
        serializer = CVESerializer(cve)
        return Response(serializer.data)
    except CVE.DoesNotExist:
        return Response({'error': 'CVE not found'}, status=status.HTTP_404_NOT_FOUND)
    
    
@api_view(['GET'])
def cve_count_view(request): 
    # Obtener el conteo total de CVEs
    total_cves = CVE.objects.count()

    # Obtener el conteo de CVEs en la última consulta desde la caché
    last_cve_count = cache.get('last_cve_count', 0)

    # Calcular el número de nuevos CVEs añadidos desde la última consulta
    new_cves_count = total_cves - last_cve_count

    # Actualizar el valor en la caché con el nuevo conteo
    cache.set('last_cve_count', total_cves)

    return Response({
        "total_cves": total_cves,
        "new_cves_added": new_cves_count # luego de un rato lo probare para ver si de verdad si funciona, sino borro new_cves_count
    })


@api_view(['GET'])
def scan_url_view(request, url_target):
    zap_api_key = os.getenv('ZAP_API_KEY')
    result = scan_url(url_target, zap_api_key)

    return Response(result)


@api_view(['GET'])
def vendor_list_view(request):
    vendors = Vendor.objects.all()
    serializer = VendorSerializer(vendors, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def product_list_view(request):
    products = Product.objects.all()
    serializer = ProductSerializer(products, many=True)
    return Response(serializer.data)
