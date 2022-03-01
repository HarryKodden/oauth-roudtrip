import os
import json
import requests
import logging

from functools import wraps

# Setup logging
log_level = os.environ.get('LOG_LEVEL', 'INFO')
logging.basicConfig(
    level=logging.getLevelName(log_level),
    format='%(asctime)s %(levelname)s %(message)s')

from flask import (Flask, make_response, render_template, redirect, request, url_for, jsonify)

issuer_info = None

try:
  CLIENT_ID = os.environ['CLIENT_ID']
  CLIENT_SECRET = os.environ['CLIENT_SECRET']
except Exception as e:
  logging.error(str(e))
  exit(1)

app = Flask(__name__)

def verify_issuer(f):

  @wraps(f)
  def decorated(*args, **kwargs):
    # Checks if the issuer info is already present, if not get it !
  
    global issuer_info
    if not issuer_info:
      try:
        ISSUER = os.environ['ISSUER']

        r = requests.get(ISSUER+'/.well-known/openid-configuration')
        if r.status_code != 200:
          raise Exception("Missing issuer configuration!")

        issuer_info = json.loads(r.text)
      except Exception as e:
        logging.error("Error retrieving issuer information: {}".format(str(e)))

    return f(*args, **kwargs)

  return decorated

def authenticated(f):

  @wraps(f)
  def decorated(*args, **kwargs):
      # Checks if the access token is present and valid.
    access_token = request.cookies.get('access_token')
    if access_token:
      logging.debug("ACCESS TOKEN: {}".format(access_token))
    else:
      return redirect(url_for('login'))
    return f(*args, **kwargs)

  return decorated


@app.route('/')
@authenticated
def main():
  # Retrieves a list of users
  access_token = request.cookies.get('access_token')

  RESOURCE_SERVER = os.environ.get('RESOURCE_SERVER','')

  r = requests.get(RESOURCE_SERVER+'/something', headers = {
    'Authorization': 'Bearer {}'.format(access_token)
  })

  if r.status_code != 200:
    return json.dumps({
      'error': 'The resource server returns an error: \n{}'.format(
        r.text)
    }), 500

  return jsonify(json.loads(r.text))

@app.route('/login')
@verify_issuer
def login():
  # Presents the login page

  CALLBACK_URL = os.environ['MY_URL']+url_for('callback')
  
  return render_template('login.html', 
                         dest = issuer_info['authorization_endpoint'],
                         client_id = os.environ['CLIENT_ID'],
                         redirect_url = CALLBACK_URL)

@app.route('/callback')
@verify_issuer
def callback():
  # Accepts the authorization code and exchanges it for access token
  authorization_code = request.args.get('authorization_code')

  if not authorization_code:
    return json.dumps({
      'error': 'No authorization code is received.'
    }), 500

  logging.debug("Authorization Code: {}".format(authorization_code))

  r = requests.post(issuer_info['token_endpoint'], data = {
    "grant_type": "authorization_code",
    "code": authorization_code,
    "client_id" : CLIENT_ID,
    "client_secret" : CLIENT_SECRET,
    "redirect_url": os.environ['MY_URL']+url_for('callback')
  })
  
  if r.status_code != 200:
    return json.dumps({
      'error': 'The authorization server returns an error: \n{}'.format(
        r.text)
    }), 500
  
  access_token = json.loads(r.text).get('access_token')

  response = make_response(redirect(url_for('main')))
  response.set_cookie('access_token', access_token)
  
  return response

if __name__ == '__main__':
   app.run(os.environ.get('HOST', '0.0.0.0'), os.environ.get('PORT', 80), debug = True)
