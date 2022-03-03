import os
import jwt
import logging
import json
import requests

from jwcrypto import jwk

cached_keys = {}

def lookup_keys(issuer):

  if issuer not in cached_keys:
    r = requests.get(issuer+'/.well-known/openid-configuration')
    if r.status_code != 200:
      raise Exception("Missing issuer configuration!")

    r = requests.get(json.loads(r.text)['jwks_uri'])
    if r.status_code != 200:
      raise Exception("Missing jwks configuration!")

    cached_keys[issuer] = r.json()['keys']

  return cached_keys.get(issuer, [])


def verify_access_token(access_token):
  try:
    ISSUER = os.environ['ISSUER']

    for key in lookup_keys(ISSUER):
      if key['use'] == 'sig':

        data = jwt.decode(
          access_token,
          jwk.JWK(**key).export_to_pem(),
          issuer = ISSUER,
          algorithms = 'RS256'
        )
        
        logging.debug(data)

        return True
    
    logging.error("No signature key found !")

  except jwt.exceptions.InvalidTokenError:
    logging.error("Invalid access token !")
  except jwt.exceptions.InvalidSignatureError:
    logging.error("Invalid signature in access token !")
  except jwt.exceptions.InvalidIssuerError:
    logging.error("Invalid Issuer in access token !")
  except jwt.exceptions.ExpiredSignatureError:
    logging.error("Access Token is expired !")
  except Exception as e:
    logging.error("Error during access token verification: {}".format(str(e)))

  return False

