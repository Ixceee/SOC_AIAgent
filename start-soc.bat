@echo off
echo 🚀 Starting SOC AI Agent with Auto-Open Dashboard...

:: Start Docker services
docker-compose up -d

echo ⏳ Waiting for services to start (30 seconds)...
timeout /t 30 /nobreak

echo 🌐 Opening dashboard in browser...
start http://localhost:8080

echo.
echo ========================================
echo ✅ SOC AI Agent is running!
echo 📊 Dashboard: http://localhost:8080
echo 🔧 API: http://localhost:11435
echo 🦙 Ollama: http://localhost:11434
echo.
echo 📋 Useful commands:
echo   View logs: docker-compose logs -f
echo   Stop services: docker-compose down
echo ========================================

:: Show logs
docker-compose logs -f