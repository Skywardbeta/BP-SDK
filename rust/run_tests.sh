#!/bin/bash

echo "Bundle Protocol SDK - Test Runner"
echo "================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    print_error "Please run this script from the rust/ directory"
    exit 1
fi

# Parse command line arguments
RUN_TESTS=true
RUN_BENCHMARKS=false
RUN_EXAMPLES=false
VERBOSE=false

for arg in "$@"; do
    case $arg in
        --benchmarks)
            RUN_BENCHMARKS=true
            shift
            ;;
        --examples)
            RUN_EXAMPLES=true
            shift
            ;;
        --all)
            RUN_BENCHMARKS=true
            RUN_EXAMPLES=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --benchmarks  Run performance benchmarks"
            echo "  --examples    Run example programs"
            echo "  --all         Run tests, benchmarks, and examples"
            echo "  --verbose     Enable verbose output"
            echo "  --help        Show this help message"
            exit 0
            ;;
    esac
done

# Build the project
print_status "Building Bundle Protocol SDK..."
if $VERBOSE; then
    cargo build
else
    cargo build > /dev/null 2>&1
fi

if [ $? -eq 0 ]; then
    print_success "Build completed successfully"
else
    print_error "Build failed"
    exit 1
fi

# Run unit tests
if $RUN_TESTS; then
    print_status "Running unit tests..."
    if $VERBOSE; then
        cargo test
    else
        cargo test > /dev/null 2>&1
    fi
    
    if [ $? -eq 0 ]; then
        print_success "All unit tests passed"
    else
        print_error "Some unit tests failed"
        if ! $VERBOSE; then
            print_warning "Run with --verbose to see detailed output"
        fi
    fi
fi

# Run benchmarks
if $RUN_BENCHMARKS; then
    print_status "Running performance benchmarks..."
    
    if command -v criterion &> /dev/null; then
        cargo bench
        
        if [ $? -eq 0 ]; then
            print_success "Benchmarks completed successfully"
            print_status "Benchmark results saved to target/criterion/"
        else
            print_error "Benchmark execution failed"
        fi
    else
        print_warning "Criterion not available, skipping benchmarks"
    fi
fi

# Run examples
if $RUN_EXAMPLES; then
    print_status "Running example programs..."
    
    # List of examples to run
    examples=(
        "comprehensive_test"
    )
    
    for example in "${examples[@]}"; do
        print_status "Running example: $example"
        
        if $VERBOSE; then
            cargo run --example "$example"
        else
            cargo run --example "$example" > /dev/null 2>&1
        fi
        
        if [ $? -eq 0 ]; then
            print_success "Example '$example' completed successfully"
        else
            print_error "Example '$example' failed"
        fi
    done
fi

# Generate test coverage report (if tarpaulin is available)
if command -v cargo-tarpaulin &> /dev/null; then
    print_status "Generating test coverage report..."
    cargo tarpaulin --out Html --output-dir target/coverage > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        print_success "Coverage report generated in target/coverage/"
    else
        print_warning "Coverage report generation failed"
    fi
else
    print_warning "cargo-tarpaulin not installed, skipping coverage report"
    print_status "Install with: cargo install cargo-tarpaulin"
fi

# Check for common issues
print_status "Running additional checks..."

# Check for unused dependencies
if command -v cargo-udeps &> /dev/null; then
    cargo +nightly udeps > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        print_success "No unused dependencies found"
    else
        print_warning "Some unused dependencies detected"
    fi
fi

# Check for security vulnerabilities
if command -v cargo-audit &> /dev/null; then
    cargo audit > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        print_success "No security vulnerabilities found"
    else
        print_warning "Security audit detected issues"
    fi
fi

# Generate documentation
print_status "Generating documentation..."
cargo doc --no-deps > /dev/null 2>&1

if [ $? -eq 0 ]; then
    print_success "Documentation generated in target/doc/"
else
    print_warning "Documentation generation failed"
fi

# Summary
echo ""
echo "================================="
print_status "Test execution completed"

if $RUN_BENCHMARKS; then
    print_status "View benchmark results: target/criterion/report/index.html"
fi

if [ -d "target/coverage" ]; then
    print_status "View coverage report: target/coverage/tarpaulin-report.html"
fi

print_status "View documentation: target/doc/bp_sdk/index.html"
echo "=================================" 