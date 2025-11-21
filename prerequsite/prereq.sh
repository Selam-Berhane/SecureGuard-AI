
#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo "  Prerequiste Check"
echo "========================================"
echo ""

# Check if Python 3 is installed
if command -v python3 &> /dev/null; then
    echo -e "${GREEN}✓ Python 3 is installed${NC}"
    echo ""

    # Get Python version
    PYTHON_VERSION=$(python3 --version 2>&1)
    echo -e "Version: ${YELLOW}${PYTHON_VERSION}${NC}"
    echo ""
else
    echo -e "${RED}✗ Python 3 is NOT installed${NC}"
    echo ""
    echo "Python 3 is required to proceed."
    echo ""
    echo "Please install Python 3 from:"
    echo "  macOS: brew install python3"
    echo "  Ubuntu/Debian: sudo apt-get install python3"
    echo "  Windows: https://www.python.org/downloads/"
    echo ""
    echo -e "${RED}Exiting... Please install Python 3 before proceeding.${NC}"
    exit 1
fi

echo ""
echo "========================================"

# Check if AWS CLI is installed
if command -v aws &> /dev/null; then
    echo -e "${GREEN}✓ AWS CLI is installed${NC}"
    echo ""

    # Get AWS CLI version
    AWS_VERSION=$(aws --version 2>&1)
    echo -e "Version: ${YELLOW}${AWS_VERSION}${NC}"
    echo ""

    # Check if AWS is configured
    if aws sts get-caller-identity &> /dev/null; then
        echo -e "${GREEN}✓ AWS CLI is configured${NC}"
        echo ""
        echo "Account Details:"
        aws sts get-caller-identity
    else
        echo -e "${YELLOW}⚠ AWS CLI is installed but not configured${NC}"
        echo ""
        echo "To configure AWS CLI, run:"
        echo "aws configure"
    fi
else
    echo -e "${RED}✗ AWS CLI is NOT installed${NC}"
    echo ""
    echo "Please visit:"
    echo "  https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
fi

echo ""
echo "========================================"

# Check if Terraform is installed
if command -v terraform &> /dev/null; then
    echo -e "${GREEN}✓ Terraform is installed${NC}"
    echo ""

    # Get Terraform version
    TERRA_VERSION=$(terraform --version 2>&1 | head -n 1)
    echo -e "Version: ${YELLOW}${TERRA_VERSION}${NC}"
    echo ""
else
    echo -e "${RED}✗ Terraform is NOT installed${NC}"
    echo ""
    echo "Please visit:"
    echo "  https://developer.hashicorp.com/terraform/install"
fi

echo ""
echo "========================================"
