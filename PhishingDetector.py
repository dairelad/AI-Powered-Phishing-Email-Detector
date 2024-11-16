import configparser
import os
from typing import Dict, List
import openai


class PhishingDetector:
    def __init__(self):
        try:  # Read API Key from config
            config = configparser.ConfigParser()
            config.read('config.ini')
            openai_key = config['api']['openai_key']
            print(f"OpenAI API Key from INI: {openai_key[:5]}...")
        except Exception as e:
            print(f"Error reading INI config: {e}")
            return
        
        self.phishing_indicators = {
            'urgency':['immediate action', 'urgent', 'act now'],
            'threats':['account suspended', 'security alert'],
            'requests':['verify your account', 'confirm your identity'],
            'credentials':['login', 'password', 'username']
        }
