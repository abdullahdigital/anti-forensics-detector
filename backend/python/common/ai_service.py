
import requests
import json
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# User provided API Key
# Loaded from .env file for security
API_KEY = os.getenv("GEMINI_API_KEY")
BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent"

class AIService:
    def __init__(self):
        # Load multiple keys from env (comma separated)
        keys_str = os.getenv("GEMINI_API_KEYS", "")
        if not keys_str:
            # Fallback to old single key if present
            keys_str = os.getenv("GEMINI_API_KEY", "")
            
        self.api_keys = [k.strip() for k in keys_str.split(',') if k.strip()]
        self.current_key_index = 0
        
        self.headers = {'Content-Type': 'application/json'}
        self.disabled_until = 0  # Timestamp to re-enable service if ALL keys fail
    def analyze_text(self, prompt, text_content=None):
        """
        Sends a prompt + optional text content to Gemini API.
        Returns the text response or None if failed.
        """
        import time
        if time.time() < self.disabled_until:
             logger.warning("AI Service: Circuit open (Quota Exceeded). Skipping request.")
             return None

        if not self.api_keys:
            logger.warning("AI Service: No API Keys configured.")
            return None
            
        full_prompt = prompt
        if text_content:
            full_prompt = f"{prompt}\n\nContext/Data:\n{text_content}"

        # Try key rotation loop
        attempts = 0
        max_attempts = len(self.api_keys)

        while attempts < max_attempts:
            current_key = self.api_keys[self.current_key_index]
            
            # Skip placeholder keys if user matches "YOUR_" pattern
            if "YOUR_" in current_key:
                logger.debug(f"Skipping placeholder key at index {self.current_key_index}")
                self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
                attempts += 1
                continue

            payload = {
                "contents": [{"parts": [{"text": full_prompt}]}]
            }
            
            try:
                url = f"{BASE_URL}?key={current_key}"
                response = requests.post(url, headers=self.headers, json=payload, timeout=15)
                
                if response.status_code == 200:
                    result = response.json()
                    try:
                        text_response = result['candidates'][0]['content']['parts'][0]['text']
                        short_preview = text_response[:100].replace('\n', ' ') + "..." if len(text_response) > 100 else text_response.replace('\n', ' ')
                        logger.info(f"AI Analysis Complete (Key Idx {self.current_key_index}): {short_preview}")
                        return text_response
                    except (KeyError, IndexError):
                        logger.error(f"AI Service: Unexpected response format: {result}")
                        return None 
                elif response.status_code == 429:
                    logger.warning(f"AI Service: Quota Exceeded for Key Idx {self.current_key_index} (429). Rotating key...")
                    self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
                    attempts += 1
                    # Retry immediately with new key
                    continue
                else:
                    logger.error(f"AI Service: Request failed with status {response.status_code}: {response.text}")
                    return None
            except requests.exceptions.RequestException as e:
                logger.error(f"AI Service: Connection error: {e}")
                return None

        logger.error("AI Service: All API Keys exhausted. Disabling AI for 60 seconds.")
        self.disabled_until = time.time() + 60
        return None

    async def analyze_text_async(self, prompt, text_content=None):
        """
        Asynchronous version of analyze_text.
        """
        import asyncio
        return await asyncio.to_thread(self.analyze_text, prompt, text_content)

# Singleton instance
ai_service = AIService()
