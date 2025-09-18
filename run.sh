#!/bin/bash

# Enterprise DevOps Platform Startup Script
# This script starts the Flask application

echo "🚀 Starting Enterprise DevOps Platform..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "Please run setup_flask_app.sh first"
    exit 1
fi

# Activate virtual environment
echo "🐍 Activating virtual environment..."
source venv/bin/activate

# Load environment variables if .env exists
if [ -f .env ]; then
    echo "⚙️  Loading environment variables..."
    export $(cat .env | grep -v '^#' | xargs)
fi

# Set Flask app if not set
export FLASK_APP=${FLASK_APP:-app.py}

# Create logs directory if it doesn't exist
mkdir -p logs

# Check if database exists, if not initialize it
if [ ! -f "enterprise_app.db" ] && [ ! -f "dev_enterprise_app.db" ]; then
    echo "🗄️  Database not found. Initializing..."
    flask db upgrade 2>/dev/null || echo "Migration not needed"
    flask init-db 2>/dev/null || echo "Database already initialized"
fi

# Determine environment and start accordingly
if [ "$FLASK_ENV" = "production" ]; then
    echo "🏭 Starting in production mode with Gunicorn..."
    exec gunicorn \
        --bind 0.0.0.0:${PORT:-5000} \
        --workers ${WORKERS:-4} \
        --timeout ${TIMEOUT:-120} \
        --access-logfile logs/access.log \
        --error-logfile logs/error.log \
        --log-level info \
        app:app
else
    echo "🔧 Starting in development mode..."
    echo "📍 Application will be available at: http://localhost:${PORT:-5000}"
    echo "🔑 Default login: admin / admin123"
    echo ""
    echo "Press Ctrl+C to stop the server"
    echo ""
    
    # Start Flask development server
    exec python app.py
fi