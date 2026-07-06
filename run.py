import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from gunicorn.app.wsgiapp import run
    run()
except ImportError:
    from app import app
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    print(f'gunicorn not found, falling back to Flask dev server on 0.0.0.0:{port}')
    app.run(host='0.0.0.0', port=port, debug=debug)
