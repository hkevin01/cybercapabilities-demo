#!/bin/bash

# Cybersecurity Demo - Universal Run Script
# This script provides one-command setup and management for the entire demo

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="docker-compose.yml"
DASHBOARD_PORT=8080
VULNERABLE_PORT=3000
SECURE_PORT=3001

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_header() {
    echo -e "${PURPLE}================================${NC}"
    echo -e "${PURPLE}$1${NC}"
    echo -e "${PURPLE}================================${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker first."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Build all images
build_images() {
    log_info "Building Docker images..."
    
    if command -v docker-compose &> /dev/null; then
        docker-compose build
    else
        docker compose build
    fi
    
    log_success "Images built successfully"
}

# Start all services
start_services() {
    log_info "Starting all services..."
    
    if command -v docker-compose &> /dev/null; then
        docker-compose up -d
    else
        docker compose up -d
    fi
    
    log_success "Services started"
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 10
    
    check_service_health
}

# Stop all services
stop_services() {
    log_info "Stopping all services..."
    
    if command -v docker-compose &> /dev/null; then
        docker-compose down
    else
        docker compose down
    fi
    
    log_success "Services stopped"
}

# Restart all services
restart_services() {
    log_info "Restarting all services..."
    stop_services
    start_services
}

# Check service health
check_service_health() {
    log_info "Checking service health..."
    
    services=(
        "Dashboard:localhost:$DASHBOARD_PORT"
        "Vulnerable App:localhost:$VULNERABLE_PORT"
        "Secure App:localhost:$SECURE_PORT"
    )
    
    for service in "${services[@]}"; do
        IFS=':' read -r name host port <<< "$service"
        
        if curl -f -s "http://$host:$port/health" > /dev/null 2>&1 || \
           curl -f -s "http://$host:$port" > /dev/null 2>&1; then
            log_success "$name is healthy (http://$host:$port)"
        else
            log_warning "$name is not responding (http://$host:$port)"
        fi
    done
}

# Show service status
show_status() {
    log_header "SERVICE STATUS"
    
    if command -v docker-compose &> /dev/null; then
        docker-compose ps
    else
        docker compose ps
    fi
    
    echo ""
    check_service_health
}

# Show logs
show_logs() {
    local service=$1
    
    if [ -z "$service" ]; then
        log_info "Showing logs for all services..."
        if command -v docker-compose &> /dev/null; then
            docker-compose logs -f
        else
            docker compose logs -f
        fi
    else
        log_info "Showing logs for $service..."
        if command -v docker-compose &> /dev/null; then
            docker-compose logs -f "$service"
        else
            docker compose logs -f "$service"
        fi
    fi
}

# Run tests
run_tests() {
    log_info "Running security tests..."
    
    # Check if test script exists
    if [ -f "./test-components.sh" ]; then
        chmod +x ./test-components.sh
        ./test-components.sh
    else
        log_warning "Test script not found. Running basic connectivity tests..."
        check_service_health
    fi
}

# Clean up everything
cleanup() {
    log_info "Cleaning up..."
    
    if command -v docker-compose &> /dev/null; then
        docker-compose down -v --remove-orphans
        docker-compose rm -f
    else
        docker compose down -v --remove-orphans
        docker compose rm -f
    fi
    
    # Remove dangling images
    if [ "$(docker images -f 'dangling=true' -q)" ]; then
        docker rmi $(docker images -f 'dangling=true' -q)
    fi
    
    log_success "Cleanup completed"
}

# Open dashboard in browser
open_dashboard() {
    local url="http://localhost:$DASHBOARD_PORT"
    
    log_info "Opening dashboard at $url"
    
    if command -v xdg-open &> /dev/null; then
        xdg-open "$url"
    elif command -v open &> /dev/null; then
        open "$url"
    elif command -v start &> /dev/null; then
        start "$url"
    else
        log_info "Please open $url in your browser"
    fi
}

# Show usage information
show_usage() {
    echo -e "${CYAN}Cybersecurity Demo - Universal Run Script${NC}"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  start, up          Start all services"
    echo "  stop, down         Stop all services"
    echo "  restart            Restart all services"
    echo "  status             Show service status"
    echo "  logs [SERVICE]     Show logs (all services or specific service)"
    echo "  test               Run security tests"
    echo "  build              Build Docker images"
    echo "  cleanup            Clean up all containers and images"
    echo "  dashboard, gui     Open dashboard in browser"
    echo "  help               Show this help message"
    echo ""
    echo "Services:"
    echo "  dashboard          Web dashboard (http://localhost:$DASHBOARD_PORT)"
    echo "  vulnerable-app     Vulnerable web app (http://localhost:$VULNERABLE_PORT)"
    echo "  secure-app         Secure web app (http://localhost:$SECURE_PORT)"
    echo ""
    echo "Examples:"
    echo "  $0 start           # Start all services"
    echo "  $0 logs dashboard  # Show dashboard logs"
    echo "  $0 test            # Run security tests"
    echo "  $0 cleanup         # Clean up everything"
}

# Main script logic
main() {
    if [ $# -eq 0 ]; then
        show_usage
        exit 0
    fi
    
    check_prerequisites
    
    case "$1" in
        start|up)
            log_header "STARTING CYBERSECURITY DEMO"
            build_images
            start_services
            echo ""
            log_success "Cybersecurity Demo is now running!"
            echo ""
            echo -e "${CYAN}Access points:${NC}"
            echo -e "  Dashboard:     ${GREEN}http://localhost:$DASHBOARD_PORT${NC}"
            echo -e "  Vulnerable App: ${YELLOW}http://localhost:$VULNERABLE_PORT${NC}"
            echo -e "  Secure App:     ${GREEN}http://localhost:$SECURE_PORT${NC}"
            echo ""
            echo -e "${BLUE}Use '$0 dashboard' to open the web interface${NC}"
            ;;
        stop|down)
            log_header "STOPPING CYBERSECURITY DEMO"
            stop_services
            ;;
        restart)
            log_header "RESTARTING CYBERSECURITY DEMO"
            restart_services
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs "$2"
            ;;
        test|tests)
            log_header "RUNNING SECURITY TESTS"
            run_tests
            ;;
        build)
            log_header "BUILDING DOCKER IMAGES"
            build_images
            ;;
        cleanup|clean)
            log_header "CLEANING UP"
            cleanup
            ;;
        dashboard|gui)
            open_dashboard
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            log_error "Unknown command: $1"
            echo ""
            show_usage
            exit 1
            ;;
    esac
}

# Trap Ctrl+C
trap 'echo -e "\n${YELLOW}Operation cancelled by user${NC}"; exit 1' INT

# Run main function
main "$@"
