import os
import jwt
import logging
import json
import requests

from jwcrypto import jwk


def verify_access_token(access_token):
  try:
    ISSUER = os.environ['ISSUER']

    r = requests.get(ISSUER+'/.well-known/openid-configuration')
    if r.status_code != 200:
      raise Exception("Missing issuer configuration!")

    r = requests.get(json.loads(r.text)['jwks'])
    if r.status_code != 200:
          raise Exception("Missing jwks configuration!")

    key = jwk.JWK(**json.loads(r.text))

    _ = jwt.decode(access_token, key.export_to_pem(),
                               issuer = ISSUER,
                               algorithms = 'RS256')
    return True
  except (jwt.exceptions.InvalidTokenError,
          jwt.exceptions.InvalidSignatureError,
          jwt.exceptions.InvalidIssuerError,
          jwt.exceptions.ExpiredSignatureError):
    logging.error("No valid JWT access token !")
  except Exception as e:
    logging.error("Error during access token verification: {}".format(str(e)))

  return False

