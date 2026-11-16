"""
Vercel Serverless Entry Point for PhishShield AI
Exposes the WSGI Flask application object for @vercel/python runtime.
"""
import sys
import os

# Ensure the root directory is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import app

# Vercel entrypoint looks for 'app'
app = app
