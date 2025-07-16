#!/bin/bash

# API Integration Security Framework - Local Setup Script
# This script sets up and runs the framework for development and demonstration

set -e

echo "🚀 API Integration Security Framework - Local Setup"
echo "================================================"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Function to check if port is available
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null ; then
        echo "⚠️  Port $port is already in use. Please stop the service using this port."
        return 1
    fi
    return 0
}

# Check required ports
echo "🔍 Checking port availability..."
if ! check_port 8000; then
    echo "FastAPI application port (8000) is in use"
    exit 1
fi

if ! check_port 5432; then
    echo "PostgreSQL port (5432) is in use - this might be okay if you have PostgreSQL running"
fi

if ! check_port 8181; then
    echo "OPA port (8181) is in use"
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file for local development..."
    cat > .env << EOF
# Environment Configuration
ENVIRONMENT=development

# Database Configuration
DATABASE_URL=postgresql://apiuser:securepassword@localhost:5432/api_security_framework

# AWS Configuration (mock for local development)
AWS_DEFAULT_REGION=us-east-1
AWS_ACCESS_KEY_ID=mock_access_key
AWS_SECRET_ACCESS_KEY=mock_secret_key

# Application Configuration
LOG_LEVEL=INFO
DEBUG=true
EOF
    echo "✅ .env file created"
fi

# Build and start services
echo "🔨 Building Docker containers..."
docker-compose build

echo "🚀 Starting services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Check service health
echo "🔍 Checking service health..."

# Check API health
if curl -s http://localhost:8000/api/v1/health/ > /dev/null; then
    echo "✅ FastAPI application is running at http://localhost:8000"
    echo "📖 API Documentation available at http://localhost:8000/docs"
else
    echo "❌ FastAPI application is not responding"
    echo "🔍 Checking logs..."
    docker-compose logs api
fi

# Check OPA health
if curl -s http://localhost:8181/health > /dev/null; then
    echo "✅ OPA Policy Engine is running at http://localhost:8181"
else
    echo "⚠️  OPA Policy Engine might not be ready yet"
fi

# Check PostgreSQL
if docker-compose exec -T db pg_isready -U apiuser > /dev/null; then
    echo "✅ PostgreSQL database is ready"
else
    echo "⚠️  PostgreSQL database might not be ready yet"
fi

echo ""
echo "🎉 Setup completed!"
echo ""
echo "📋 Available endpoints:"
echo "   • API Documentation: http://localhost:8000/docs"
echo "   • Health Check: http://localhost:8000/api/v1/health/"
echo "   • Integration Status: http://localhost:8000/api/v1/integrations/status"
echo "   • OPA Policies: http://localhost:8181/v1/policies"
echo ""
echo "🔑 Demo credentials:"
echo "   • Email: admin@medconnect.com"
echo "   • Password: demo_password"
echo ""
echo "🛠  Useful commands:"
echo "   • View logs: docker-compose logs -f"
echo "   • Stop services: docker-compose down"
echo "   • Rebuild: docker-compose down && docker-compose build && docker-compose up -d"
echo ""
echo "📚 Test the API:"
echo "   curl -X POST http://localhost:8000/api/v1/auth/login \\"
echo "        -H 'Content-Type: application/json' \\"
echo "        -d '{\"email\":\"admin@medconnect.com\",\"password\":\"demo_password\"}'"
