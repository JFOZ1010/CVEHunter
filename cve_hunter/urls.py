from django.urls import path
from .views import (
    cve_list_view,
    cve_detail_view,
    #scan_url_view,
    vendor_list_view,
    product_list_view,
)

urlpatterns = [
    path('cves/', cve_list_view, name='cve-list'),
    path('cves/<int:pk>/', cve_detail_view, name='cve-detail'),
    #path('scan/', scan_url_view, name='scan-url'),
    path('vendors/', vendor_list_view, name='vendor-list'),
    path('products/', product_list_view, name='product-list'),
]