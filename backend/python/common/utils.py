# backend/python/config/settings.py
import os

class Settings:
    DATABASE_TYPE = os.getenv('DATABASE_TYPE', 'sqlite') # 'sqlite' or 'mongodb'
    # Add other Python-specific configurations here

settings = Settings()