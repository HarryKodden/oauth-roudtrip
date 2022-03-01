import base64
import json
import os
import jwt
import time
import logging

from cryptography.fernet import Fernet
from jwcrypto import jwk

signing_key = jwk.JWK.generate(kty='RSA', size=2048, alg='RSA-OAEP-256', use='enc', kid='12345')
encryption_key = Fernet.generate_key()

ISSUER = os.environ['MY_URL']

CODE_LIFE_SPAN = 600
JWT_LIFE_SPAN = 1800

authorization_codes = {}

def public_key():
  return signing_key.export_public()

def authenticate_user_credentials(username, password):
  logging.debug("Authenticate user...")
  return True

def authenticate_client(client_id, client_secret):
  logging.debug("Authenticate client...")
  return True

def verify_client_info(client_id, redirect_url):
  logging.debug("Verify client...")
  return True

def generate_access_token():
  payload = {
    "iss": ISSUER,
    "exp": time.time() + JWT_LIFE_SPAN
  }

  private_key = signing_key.export_to_pem(private_key=True, password=None)

  access_token = jwt.encode(payload, private_key, algorithm = 'RS256')

  return access_token

def generate_authorization_code(client_id, redirect_url):
  f = Fernet(encryption_key)

  authorization_code = f.encrypt(json.dumps({
    "client_id": client_id,
    "redirect_url": redirect_url,
  }).encode())

  authorization_code = base64.b64encode(authorization_code, b'-_').decode().replace('=', '')

  expiration_date = time.time() + CODE_LIFE_SPAN

  authorization_codes[authorization_code] = {
    "client_id": client_id,
    "redirect_url": redirect_url,
    "exp": expiration_date
  }

  return authorization_code

def verify_authorization_code(authorization_code, client_id, redirect_url):
  record = authorization_codes.get(authorization_code)
  if not record:
    return False

  client_id_in_record = record.get('client_id')
  redirect_url_in_record = record.get('redirect_url')
  exp = record.get('exp')

  if client_id != client_id_in_record or \
     redirect_url != redirect_url_in_record:
    return False

  if exp < time.time():
    return False

  del authorization_codes[authorization_code]

  return True
