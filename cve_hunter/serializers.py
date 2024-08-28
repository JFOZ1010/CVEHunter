from rest_framework import serializers
from .models import CVE, Vendor, Product

class CVESerializer(serializers.ModelSerializer):
    class Meta:
        model = CVE
        fields = '__all__'

class VendorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = '__all__'

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = '__all__'