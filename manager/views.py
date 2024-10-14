import base64
import datetime
import json
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from .models import activation_key

# List Encryption Key Views. Column : Name(password), Key, Expired, Is Used

# Make New Encryption Key Views : input : Name, days

def create_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(password: str, expiry_days: int) -> str:
    salt = os.urandom(16)
    key = create_key(password, salt)
    fernet = Fernet(key)
    expiry_date = datetime.datetime.now() + datetime.timedelta(days=expiry_days)
    data_with_expiry = json.dumps({"expiry_date": expiry_date.isoformat()})
    encrypted_data = fernet.encrypt(data_with_expiry.encode())
    return base64.urlsafe_b64encode(salt + encrypted_data).decode()

def decrypt_data(encrypted_data: str, password: str) -> str:
    decoded = base64.urlsafe_b64decode(encrypted_data)
    salt = decoded[:16]
    encrypted = decoded[16:]
    key = create_key(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted).decode()

class EncryptionKeyListView(View):
    def get(self, request):
        keys = activation_key.objects.all()
        for key in keys:
            try:
                decrypted_data = decrypt_data(key.key, key.name)
                data = json.loads(decrypted_data)
                expiry_date = timezone.datetime.fromisoformat(data['expiry_date'])
                expiry_date = timezone.localtime(expiry_date)
                key.expired = expiry_date < timezone.localtime(timezone.now())
            except Exception:
                key.expired = True
            
            # Tambahkan atribut password untuk ditampilkan
            key.password = key.name
        
        context = {'keys': keys}
        return render(request, 'manager/key_list.html', context)

class CreateEncryptionKeyView(View):
    def post(self, request):
        name = request.POST.get('name')
        days = int(request.POST.get('days', 30))
        
        encrypted = encrypt_data(name, days)
        
        activation_key.objects.create(
            name=name,
            key=encrypted,
            is_used=False
        )
        
        return redirect('key_list')

@method_decorator(csrf_exempt, name='dispatch')
class ActivateKeyView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            key = data.get('key')
            password = data.get('password')
            
            if not key:
                return JsonResponse({'error': 'Key not found in data'}, status=200)
            
            activation = activation_key.objects.filter(key=key).first()
            
            if not activation:
                return JsonResponse({'error': 'Invalid Key'}, status=200)
            
            if activation.is_used:
                return JsonResponse({'error': 'Used'}, status=200)
            
            if password != activation.name:
                return JsonResponse({'error': 'Invalid Key Name'}, status=200)
            
            activation.is_used = True
            activation.save()
            
            return JsonResponse({'message': 'Successfully'}, status=200)
        
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
        
def activate_page(request):
    return render(request, 'manager/activate.html')

# Contoh curl untuk mengaktifkan kunci:
# curl -X POST -H "Content-Type: application/json" -d '{"key":"kunci_aktivasi_anda"}' http://localhost:8000/activate/
# curl -X POST -H "Content-Type: application/json" -d '{"key":"p6vOtYGoYALGaM-nQ374Q2dBQUFBQUJtN1VZWWhoUWVBbmNJWDExZmFsS19CVk5LcFBQcXZmdU9jUk9FWHRmVEg0STJ1d1ZVcW5uQ2EtS05vWkRkWS1rLTRIRll2LW40U3JYel9aTlRxeDRuS1VBZnVjejJTcGRWeng1UV9xMExEdFFqa2MxeEs4cjRIT1ZPZkF2YWhwWGZmTWhU"}' http://127.0.0.1:8000/activate/

# Gantilah 'kunci_aktivasi_anda' dengan kunci aktivasi yang sebenarnya
# dan 'http://localhost:8000/activate/' dengan URL endpoint yang sesuai

def delete_key(request, key_id):
    key = get_object_or_404(activation_key, id=key_id)
    key.delete()
    return redirect('key_list')

