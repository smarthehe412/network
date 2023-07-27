package main

import (
	"log"
	"net"
	"strings"
	"errors"
)
func resolveSocks(conn net.Conn, serverIP string, IPtype byte, socksType string, isWritten bool) (net.Conn, error) {
	if socksType == "direct" {
		return socksDirect(conn, serverIP, IPtype, isWritten)
	} else if socksType == "ban" {
		return socksBan(conn, serverIP, IPtype, isWritten)
	} else if socksType == "full" {
		return socksFull(conn, serverIP, IPtype, isWritten)
	} else {
		return nil, errors.New("Invalid socksType")
	}
}
func socksDirect(conn net.Conn, serverIP string, IPtype byte, isWritten bool) (net.Conn, error) {
	log.Println(serverIP) // 监视

	// 分流策略
	var target string
	target = serverIP

	if target == serverIP {
		targetConn, err := connectTCPServer(conn, serverIP, isWritten)
		return targetConn, err
	} else {
		targetConn, err := connectTCPProxy(conn, serverIP, target, isWritten)
		return targetConn, err
	}
}
func socksBan(conn net.Conn, serverIP string, IPtype byte, isWritten bool) (net.Conn, error) {
	log.Println(serverIP) // 监视

	// 分流策略
	var target string
	if IPtype == 0x03 && strings.Contains(serverIP, "bilibili") {
		target = IPList[0]
	} else {
		target = serverIP
	}

	if target == serverIP {
		targetConn, err := connectTCPServer(conn, serverIP, isWritten)
		return targetConn, err
	} else {
		targetConn, err := connectTCPProxy(conn, serverIP, target, isWritten)
		return targetConn, err
	}
}
func socksFull(conn net.Conn, serverIP string, IPtype byte, isWritten bool) (net.Conn, error) {
	log.Println(serverIP) // 监视

	// 分流策略
	var target string
	if IPtype == 0x03 && strings.Contains(serverIP, "bilibili") {
		target = IPList[0]
	} else if IPtype == 0x03 && strings.Contains(serverIP, "baidu") {
		target = IPList[1]
	} else if IPtype == 0x03 && strings.Contains(serverIP, "codeforces") {
		target = IPList[2]
	} else if IPtype == 0x03 && strings.Contains(serverIP, "sjtu") {
		target = IPList[3]
	} else {
		target = serverIP
	}

	if target == serverIP {
		targetConn, err := connectTCPServer(conn, serverIP, isWritten)
		return targetConn, err
	} else {
		targetConn, err := connectTCPProxy(conn, serverIP, target, isWritten)
		return targetConn, err
	}
}