#!/usr/bin/env python3
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for API endpoints

# All UI-related functionality has been removed
# Only keeping essential backend functionality

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)