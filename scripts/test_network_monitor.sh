#!/bin/bash

# Color definition
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test port list (consistent with policy.toml)
PORTS=(1234 2333 8888 9999 10086 8080 8443)
TEST_DURATION=5

echo -e "${GREEN}Starting network monitoring test...${NC}"

# Create temporary Python script
cat > /tmp/test_server.py << 'EOF'
import socket
import sys
import time
import signal
import threading

def handle_client(client_socket):
    try:
        # Receive data
        data = client_socket.recv(1024)
        # Send response
        client_socket.send(b"Hello from server!")
    finally:
        client_socket.close()

def create_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('127.0.0.1', port))
        server.listen(5)
        print(f"Server listening on port {port}")
        return server
    except Exception as e:
        print(f"Error binding to port {port}: {e}")
        return None

def main():
    if len(sys.argv) != 2:
        print("Usage: script.py <port>")
        sys.exit(1)
    
    port = int(sys.argv[1])
    server = create_server(port)
    if not server:
        sys.exit(1)
    
    def signal_handler(sig, frame):
        server.close()
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        while True:
            client, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(client,))
            thread.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()

if __name__ == "__main__":
    main()
EOF

# Create client script
cat > /tmp/test_client.py << 'EOF'
import socket
import sys
import time

def test_connection(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', port))
        sock.send(b"Hello from client!")
        data = sock.recv(1024)
        print(f"Received from server: {data.decode()}")
        sock.close()
        return True
    except Exception as e:
        print(f"Error connecting to port {port}: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: script.py <port>")
        sys.exit(1)
    
    port = int(sys.argv[1])
    test_connection(port)
EOF

# Test each port
for PORT in "${PORTS[@]}"; do
    echo -e "${YELLOW}Testing port $PORT${NC}"
    
    # Start server
    python3 /tmp/test_server.py $PORT &
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 1
    
    # Run client test
    python3 /tmp/test_client.py $PORT
    
    # Wait a while to observe results
    sleep $TEST_DURATION
    
    # Close server
    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
    
    echo -e "${GREEN}Port $PORT test completed${NC}"
    echo "----------------------------------------"
done

# Clean up temporary files
rm -f /tmp/test_server.py /tmp/test_client.py

echo -e "${GREEN}Test completed${NC}" 
