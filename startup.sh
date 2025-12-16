#!/bin/bash

# Wait for all services to be healthy
echo "⏳ Waiting for services to start..."
sleep 30

# Check if dashboard is accessible
if curl -f http://localhost:8080 > /dev/null 2>&1; then
    echo "✅ Dashboard is ready!"
    echo "🌐 Opening dashboard in browser..."
    
    # Auto-open based on OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open http://localhost:8080
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        open http://localhost:8080
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]]; then
        start http://localhost:8080
    else
        echo "📱 Please open manually: http://localhost:8080"
    fi
else
    echo "❌ Dashboard not accessible yet"
    echo "📱 Please open manually later: http://localhost:8080"
fi