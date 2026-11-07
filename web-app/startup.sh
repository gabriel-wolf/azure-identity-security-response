
#!/bin/bash
set -e

cd /home/site/wwwroot

echo "Installing Python dependencies..."
python -m pip install --no-cache-dir -r requirements.txt

echo "Recording application startup time..."
date -u +"%Y-%m-%d %H:%M:%S UTC" > deployment_timestamp.txt

echo "Starting Azure Identity Security Response Platform..."
exec python -m uvicorn main:app --host 0.0.0.0 --port 8000
