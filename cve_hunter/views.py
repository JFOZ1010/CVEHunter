from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from .models import CVE, Vendor, Product
from .serializers import CVESerializer, VendorSerializer, ProductSerializer
from .cve_methods import fetch_recent_cves
#, scan_url_for_cves


@api_view(['GET'])
def cve_list_view(request):
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

""" @api_view(['GET'])
def scan_url_view(request):
    url = request.query_params.get('url', None)
    if url:
        cves = scan_url_for_cves(url)
        if cves:
            return Response({'cves': cves}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'No CVEs found for the given URL'}, status=status.HTTP_200_OK)
    return Response({'error': 'URL not provided'}, status=status.HTTP_400_BAD_REQUEST) """

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
