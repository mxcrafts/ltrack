#!/bin/bash

# Color definition
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Command list from policy.toml
COMMANDS=("bash" "python" "nginx")
TEST_DURATION=2

echo -e "${GREEN}Starting process execution monitoring test...${NC}"

# Test each command
for CMD in "${COMMANDS[@]}"; do
    echo -e "${YELLOW}Testing command: $CMD${NC}"
    
    case $CMD in
        "python")
            # Create temporary Python script
            cat > /tmp/test.py << 'EOF'
print("Hello from Python test script!")
EOF
            echo "Executing Python script..."
            python3 /tmp/test.py
            rm -f /tmp/test.py
            ;;
            
        "nginx")
            echo "Testing nginx command..."
            # If nginx is installed, try to start it
            if command -v nginx &> /dev/null; then
                sudo nginx -t
            else
                echo -e "${RED}nginx is not installed, skipping test${NC}"
            fi
            ;;
            
        "bash")
            echo "Testing bash command..."
            # Create and execute temporary bash script
            cat > /tmp/test.sh << 'EOF'
#!/bin/bash
echo "Hello from bash test script!"
EOF
            chmod +x /tmp/test.sh
            bash /tmp/test.sh
            rm -f /tmp/test.sh
            ;;
            
        *)
            echo "Executing generic command: $CMD"
            $CMD --version || $CMD -v || echo "Command execution failed"
            ;;
    esac
    
    # Wait for a while to observe logs
    echo "Waiting for log output..."
    sleep $TEST_DURATION
    echo -e "${GREEN}Command $CMD test completed${NC}"
    echo "----------------------------------------"
done

echo -e "${GREEN}Test completed${NC}"
echo -e "${YELLOW}Please check the log file to verify if the process execution is captured correctly${NC}"
echo -e "Log location: /var/log/ltrack/app.log"

# Display recent relevant logs
echo -e "${GREEN}Recent process execution logs:${NC}"
if [ -f /var/log/ltrack/app.log ]; then
    echo "grep 'Process execution detected' /var/log/ltrack/app.log | tail -n 10"
    grep "Process execution detected" /var/log/ltrack/app.log | tail -n 10
else
    echo -e "${RED}Log file does not exist${NC}"
fi 
