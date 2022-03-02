import json
import os

import requests
from auth import verify_access_token
from flask import Flask, request, jsonify
from functools import wraps

import logging

# Setup logging
log_level = os.environ.get('LOG_LEVEL', 'INFO')
logging.basicConfig(
    level=logging.getLevelName(log_level),
    format='%(asctime)s %(levelname)s %(message)s')

app = Flask(__name__)

def check_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
      # Checks if the access token is present and valid.
      auth_header = request.headers.get('Authorization')
      if not auth_header or 'Bearer' not in auth_header:
        return jsonify({
          'error': 'Access token does not exist.'
        }), 400
      
      access_token = auth_header[7:]

      if access_token and verify_access_token(access_token):
        logging.info("Access token is valid !")
      else:
        return jsonify({
          'error': 'Access token is invalid.'
        }), 400
      return f(*args, **kwargs)

    return decorated


@app.route('/something', methods = ['GET'])
@check_token
def something():
  # Returns something...

  headers = {"Authorization": "Bearer "+os.environ['RESOURCE_API_KEY']}
  r = requests.get(os.environ["RESOURCE_API_URL"], headers=headers)
  logging.debug(r.text)
  return jsonify(json.loads(r.text))
    

if __name__ == '__main__':
  app.run(os.environ.get('HOST', '0.0.0.0'), os.environ.get('PORT', 80), debug = True)
