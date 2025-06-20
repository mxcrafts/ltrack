#!/bin/bash

# Color definition
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test port list (consistent with policy.toml)
PORTS=(1234 2333 8888 9999 10086 8080 8443)
# 缩短测试时间以加快测试
TEST_DURATION=2
# 每个端口测试次数
TEST_ATTEMPTS=3

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                 网络监控测试工具                                ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo -e "${GREEN}[+] 启动网络监控测试，将测试以下端口: ${YELLOW}${PORTS[@]}${NC}"
echo -e "${GREEN}[+] 每个端口将尝试 ${TEST_ATTEMPTS} 次连接${NC}"
echo -e "${GREEN}[+] 请确保ltrack程序已经以root权限启动并且监控功能已开启${NC}"
echo

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

def test_connection(port, num):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', port))
        sock.send(f"Hello from client! Test #{num}".encode())
        data = sock.recv(1024)
        print(f"[Test #{num}] Received from server: {data.decode()}")
        sock.close()
        return True
    except Exception as e:
        print(f"[Test #{num}] Error connecting to port {port}: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: script.py <port> <attempt_number>")
        sys.exit(1)
    
    port = int(sys.argv[1])
    attempt = int(sys.argv[2])
    test_connection(port, attempt)
EOF

# 创建UDP测试脚本
cat > /tmp/test_udp.py << 'EOF'
import socket
import sys

def test_udp(port, num):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(f"UDP test packet #{num}".encode(), ('127.0.0.1', port))
        print(f"[UDP Test #{num}] Sent UDP packet to port {port}")
        sock.close()
        return True
    except Exception as e:
        print(f"[UDP Test #{num}] Error sending UDP to port {port}: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: script.py <port> <attempt_number>")
        sys.exit(1)
    
    port = int(sys.argv[1])
    attempt = int(sys.argv[2])
    test_udp(port, attempt)
EOF

# Test each port
for PORT in "${PORTS[@]}"; do
    echo -e "${YELLOW}[*] 测试端口 $PORT ${NC}"
    
    # Start server
    python3 /tmp/test_server.py $PORT &
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 1
    
    # Run client test multiple times
    for ((i=1; i<=$TEST_ATTEMPTS; i++)); do
        echo -e "${GREEN}[*] TCP测试 #$i - 端口 $PORT${NC}"
        python3 /tmp/test_client.py $PORT $i
        sleep 0.5
    done
    
    # Test UDP traffic
    for ((i=1; i<=$TEST_ATTEMPTS; i++)); do
        echo -e "${GREEN}[*] UDP测试 #$i - 端口 $PORT${NC}"
        python3 /tmp/test_udp.py $PORT $i
        sleep 0.5
    done
    
    # Wait a while to observe results
    echo -e "${BLUE}[*] 等待 ${TEST_DURATION} 秒观察结果...${NC}"
    sleep $TEST_DURATION
    
    # Close server
    echo -e "${GREEN}[*] 终止服务器进程 PID=$SERVER_PID${NC}"
    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
    
    echo -e "${GREEN}[+] 端口 $PORT 测试完成${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
done

# Clean up temporary files
rm -f /tmp/test_server.py /tmp/test_client.py /tmp/test_udp.py

echo
echo -e "${GREEN}[+] 测试完成，请检查ltrack日志以确认网络事件是否被正确捕获${NC}" 
echo -e "${YELLOW}[!] 如果没有捕获到事件，请确保：${NC}" 
echo -e "${YELLOW}   1. ltrack程序以root权限运行${NC}" 
echo -e "${YELLOW}   2. 网络监控功能已开启${NC}" 
echo -e "${YELLOW}   3. 监控的端口配置正确（当前测试端口: ${PORTS[@]}）${NC}" 
