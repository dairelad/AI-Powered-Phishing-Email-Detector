'''
Phishing Email Detector
Author: Daire Curran
Developed with assistance from Claude 3.5 Sonnet (Anthropic, 2024)
Date: November 2024
'''

import configparser
from typing import Dict, List
import openai
import datetime
import json
import logging
import httpx

class PhishingDetector:
    def __init__(self):
        try:  # Read API Key from config
            config = configparser.ConfigParser()
            config.read('config.ini')
            openai_key = config['api']['openai_key']
            print(f"OpenAI API Key Loaded from INI Config: {openai_key[:5]}...\n")
        except Exception as e:
            print(f"Error reading INI config: {e}")
            return
        
        self.phishing_indicators = {
            'urgency':['immediate action', 'urgent', 'act now'],
            'threats':['account suspended', 'security alert'],
            'requests':['verify your account', 'confirm your identity'],
            'credentials':['login', 'password', 'username']
        }

        proxy = False
        if proxy:
            http_proxy = config['proxy']['HTTP_PROXY']
            https_proxy = config['proxy']['HTTPS_PROXY']
            proxies = {
                "http://": http_proxy,
                "https://": https_proxy,
            }

            ## Code below can be used to troubleshoot connection from local machine to openai API
            # try:
            #     print(proxies)
            #     response = httpx.get("https://api.openai.com/v1/models", verify=False, timeout=10.0)
            #     print("Connection successful:", response.status_code)
            #     print(response.json())
            # except httpx.RequestError as e:
            #     print("Request failed:", e)

            self.client = openai.OpenAI(api_key=openai_key, http_client=httpx.Client(proxies=proxies, verify=False))
        else: 
            self.client = openai.OpenAI(api_key=openai_key, http_client=httpx.Client(verify=False)) # temp disable ssl verification

    def analyze_email(self, email_content: str) -> Dict: #python hint, email_content takes a string as input and function returns a dict
        """
        Analyzes email content for potential phishing attempts using both
        rule-based and AI approaches.
        """
        results = {
            'rule_based_score': self._rule_based_analysis(email_content),
            'ai_analysis': self._ai_analysis(email_content),
            'combined_risk': 0.0
        }
        
        # Combine both scores with weights
        results['combined_risk'] = (
            results['rule_based_score'] * 0.3 + # 30% weight to rule-based score
            results['ai_analysis']['risk_score'] * 0.7 # 70% weight to AI score
        )
        
        return results
    
    def _rule_based_analysis(self, content: str) -> float:
        """
        Performs traditional rule-based analysis of the email content.
        """
        content = content.lower()
        score = 0.0
        
        for category, indicators in self.phishing_indicators.items():
            for indicator in indicators:
                if indicator in content:
                    score += 0.2  # Increment score for each match
                    
        return min(score, 1.0)  # Normalize to 0-1
    
    def _ai_analysis(self, content: str) -> Dict:
        """
        Uses OpenAI's API to perform advanced analysis of the email content.
        Returns structured analysis including risk score, identified threats,
        and detailed reasoning.
        """

        prompt = f"""
        Analyze this email for phishing attempts. Provide analysis in the following JSON format:
        {{
            "risk_score": (float between 0-1),
            "threat_indicators": [list of specific suspicious elements found],
            "reasoning": [list of detailed explanations],
            "confidence": (float between 0-1),
            "recommended_actions": [list of recommended user actions]
        }}
        
        Consider the following in your analysis:
        1. Linguistic patterns and urgency
        2. Technical indicators (links, headers)
        3. Social engineering tactics
        4. Credential harvesting attempts
        
        Email content:
        {content}
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert. Provide analysis in valid JSON format only."},
                    {"role": "user", "content": prompt}
                ],
            )
            
            # Parse the JSON response
            try:
                analysis_result = json.loads(response.choices[0].message.content)
                
                # Validate the required fields
                required_fields = ['risk_score', 'threat_indicators', 'reasoning', 'confidence']
                if not all(field in analysis_result for field in required_fields):
                    raise ValueError("Missing required fields in AI response")
                
                # Ensure risk_score is within bounds
                analysis_result['risk_score'] = max(0, min(1, float(analysis_result['risk_score'])))
                
                # Add metadata about the analysis
                analysis_result['timestamp'] = datetime.datetime.now().isoformat()
                analysis_result['model_version'] = "gpt-4"
                
                # Calculate a confidence-adjusted risk score
                analysis_result['adjusted_risk_score'] = (
                    analysis_result['risk_score'] * analysis_result['confidence']
                )
                
                return {
                    'risk_score': analysis_result['adjusted_risk_score'],
                    'analysis': analysis_result,
                    'detailed_threats': {
                        'indicators': analysis_result['threat_indicators'],
                        'reasoning': analysis_result['reasoning'],
                        'actions': analysis_result.get('recommended_actions', [])
                    }
                }
                
            except json.JSONDecodeError as e:
                logging.error(f"Failed to parse AI response as JSON: {e}")
                return self._fallback_analysis()
                
        except Exception as e:
            logging.error(f"AI analysis failed: {str(e)}")
            return self._fallback_analysis()
    
    def _fallback_analysis(self) -> Dict:
        """
        Provides a fallback analysis when AI analysis fails.
        """
        return {
            'risk_score': 0.5,  # Neutral score when uncertain
            'analysis': {
                'risk_score': 0.5,
                'threat_indicators': ['Analysis failed - using fallback'],
                'reasoning': ['AI analysis encountered an error'],
                'confidence': 0.0,
                'timestamp': datetime.datetime.now().isoformat()
            },
            'detailed_threats': {
                'indicators': ['Analysis failed'],
                'reasoning': ['Fallback analysis activated due to error'],
                'actions': ['Please retry analysis or use alternative methods']
            }
        }

# Example usage
if __name__ == "__main__":
    detector = PhishingDetector()
    
    sample_email = """
    Dear User,
    
    We've noticed unusual activity in your account. Please verify your identity
    immediately by clicking the link below and entering your login credentials.
    
    If you don't act within 24 hours, your account will be suspended.
    
    Best regards,
    Security Team
    """
    
    results = detector.analyze_email(sample_email)
    print(f"Analysis Results:")
    print(f"Rule-based Score: {results['rule_based_score']}")
    print(f"OpenAI Analysis Score: {results['ai_analysis']['risk_score']}")
    print(f"Combined Risk Score: {results['combined_risk']}")
    print(f"\nDetailed AI Analysis:")
    print(results['ai_analysis']['analysis'])