import os
import sys
from flask import Flask, jsonify
from flask_cors import CORS

# Add the parent directory to the sys.path to allow importing anti_forensics
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from anti_forensics.router import ads_bp
from anti_forensics.analysis_router import analysis_bp

app = Flask(__name__)

# Configure CORS properly
CORS(app, 
     origins=["http://localhost:4200"],  # Angular dev server
     supports_credentials=True,
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"])

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:4200')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

app.register_blueprint(ads_bp, url_prefix='/api/ads')
app.register_blueprint(analysis_bp, url_prefix='/api/analysis')

if __name__ == '__main__':
    # Run on different port than Angular (4200)
    app.run(debug=True, port=5000, host='0.0.0.0')