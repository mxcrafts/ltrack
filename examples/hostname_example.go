package main

import (
	"fmt"
	"log"

	"github.com/mxcrafts/ltrack/pkg/utils"
)

func main() {
	// 获取当前主机的hostname
	hostname, err := utils.GetHostname()
	if err != nil {
		log.Fatalf("Failed to get hostname: %v", err)
	}

	fmt.Printf("Current hostname: %s\n", hostname)
	
	// 可以用于日志记录、监控等场景
	fmt.Printf("System info - Host: %s\n", hostname)
}
