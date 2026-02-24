"""
WSGI entry point.

Run with Gunicorn:
    gunicorn --workers 4 --bind 0.0.0.0:5000 wsgi:application

Run in development:
    flask run --debug
"""
from app import create_app

application = create_app()

if __name__ == "__main__":
    application.run()
