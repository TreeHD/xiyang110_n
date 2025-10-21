// nat_setup.go
package main

import (
    "os/exec"
    "strings"
	"io/ioutil"
	"log"
)

func runIPCommand(args ...string) error {
	cmd := exec.Command("ip", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command 'ip %s' failed: %v, output: %s", strings.Join(args, " "), err, string(output))
	}
	return nil
}

func enableIPForwarding() error {
	log.Println("Enabling kernel IP forwarding...")
    return ioutil.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
}

func setupNAT(tunInterfaceName string) error {
	log.Printf("Setting up iptables NAT rule for %s...", tunInterfaceName)
	// 首先，检查规则是否已存在，避免重复添加
	checkCmd := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE")
	if err := checkCmd.Run(); err == nil {
		log.Println("iptables NAT rule already exists.")
		return nil
	}
	
	// 添加规则
	cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add iptables rule: %v, output: %s", err, string(output))
	}
	log.Println("iptables NAT rule added successfully.")
	return nil
}
