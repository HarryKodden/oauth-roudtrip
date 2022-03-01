import os
import json
import urllib.parse as urlparse
import logging

from auth import (authenticate_user_credentials, authenticate_client,
                  generate_access_token, generate_authorization_code, 
                  verify_authorization_code, verify_client_info,
                  JWT_LIFE_SPAN, public_key)

from flask import Flask, redirect, render_template, request, url_for
from urllib.parse import urlencode

# Setup logging
log_level = os.environ.get('LOG_LEVEL', 'INFO')
logging.basicConfig(
    level=logging.getLevelName(log_level),
    format='%(asctime)s %(levelname)s %(message)s')


app = Flask(__name__)

@app.route('/authorize')
def auth():
  # Describe the access request of the client and ask user for approval
  client_id = request.args.get('client_id')
  redirect_url = request.args.get('redirect_url')

  if None in [ client_id, redirect_url ]:
    return json.dumps({
      "error": "invalid_request"
    }), 400

  if not verify_client_info(client_id, redirect_url):
    return json.dumps({
      "error": "invalid_client"
    })

  return render_template('grant_access.html',
                         client_id = client_id,
                         redirect_url = redirect_url)

def process_redirect_url(redirect_url, authorization_code):
  # Prepare the redirect URL
  url_parts = list(urlparse.urlparse(redirect_url))
  queries = dict(urlparse.parse_qsl(url_parts[4]))
  queries.update({ "authorization_code": authorization_code })
  url_parts[4] = urlencode(queries)
  url = urlparse.urlunparse(url_parts)
  return url


@app.route('/.well-known/openid-configuration', methods = ['GET'])
def wellknown():
  return json.dumps({
      "issuer": os.environ['MY_URL'],
      "authorization_endpoint": os.environ['MY_URL']+url_for('auth'),
      "token_endpoint": os.environ['MY_URL']+url_for('exchange_for_token'),
      "jwks": os.environ['MY_URL']+url_for('jwks')
    })


@app.route('/signin', methods = ['POST'])
def signin():
  # Issues authorization code
  username = request.form.get('username')
  password = request.form.get('password')
  client_id = request.form.get('client_id')
  redirect_url = request.form.get('redirect_url')

  if None in [ username, password, client_id, redirect_url ]:
    return json.dumps({
      "error": "invalid_request"
    }), 400

  if not verify_client_info(client_id, redirect_url):
    return json.dumps({
      "error": "invalid_client"
    })

  if not authenticate_user_credentials(username, password):
    return json.dumps({
      'error': 'access_denied'
    }), 401

  authorization_code = generate_authorization_code(client_id, redirect_url)

  url = process_redirect_url(redirect_url, authorization_code)

  return redirect(url, code = 303)

@app.route('/jwks', methods = ['get'])
def jwks():
    return public_key(), 200

@app.route('/token', methods = ['POST'])
def exchange_for_token():
  # Issues access token
  authorization_code = request.form.get('code')
  client_id = request.form.get('client_id')
  client_secret = request.form.get('client_secret')
  redirect_url = request.form.get('redirect_url')

  logging.debug(json.dumps(request.form))

  if None in [ authorization_code, client_id, client_secret, redirect_url ]:
    return json.dumps({
      "error": "invalid_request"
    }), 400

  if not authenticate_client(client_id, client_secret):
    return json.dumps({
      "error": "invalid_client"
    }), 400

  if not verify_authorization_code(authorization_code, client_id, redirect_url):
    return json.dumps({
      "error": "access_denied"
    }), 400

  access_token = generate_access_token()

  return json.dumps({ 
    "access_token": access_token,
    "token_type": "JWT",
    "expires_in": JWT_LIFE_SPAN
  })

if __name__ == '__main__':
  app.run(os.environ.get('HOST', '0.0.0.0'), os.environ.get('PORT', 80), debug = True)
