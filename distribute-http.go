package main

import (
	"strings"
	"log"
	"fmt"
	"net"
	"errors"
)
func resolveHttp(conn net.Conn, serverIP, finalIP, httpType string) (net.Conn, error) {
	if httpType == "direct" {
		return httpDirect(conn, serverIP, finalIP)
	} else if httpType == "ban" {
		return httpBan(conn, serverIP, finalIP)
	} else if httpType == "full" {
		return httpFull(conn, serverIP, finalIP)
	} else {
		return nil, errors.New("Invalid httpType")
	}
}
func resolveTLS(conn net.Conn, serverIP, finalIP, httpType string) (net.Conn, error) {
	if TLSType == "direct" {
		return httpDirect(conn, serverIP, finalIP)
	} else if TLSType == "ban" {
		return httpBan(conn, serverIP, finalIP)
	} else if TLSType == "full" {
		return httpFull(conn, serverIP, finalIP)
	} else {
		return nil, errors.New("Invalid TLSType")
	}
}
func readHttpHead(conn net.Conn) ([]byte, bool, string, error) {
	httpHead := make([]byte, 1024)
	_, err := conn.Read(httpHead)
	if err != nil {
		return nil, false, "", err
	}
	if strings.Contains(string(httpHead), "Host:") {
		index := strings.Index(string(httpHead), "Host:")
		var ed int
		for ed = index + 6; ; ed++ {
			if 'A' <= httpHead[ed] && httpHead[ed] <= 'Z' {
				break
			}
		}
		return httpHead, false, string(httpHead[index+6 : ed]), nil
	} else {
		// https://www.lmlphp.com/user/154257/article/item/5180230/
		var allLen, ed, IPLen int = int(httpHead[3])<<8|int(httpHead[4]), 43, -1
		ed += int(httpHead[ed]) + 1
		ed += (int(httpHead[ed])<<8|int(httpHead[ed+1])) + 2
		ed += int(httpHead[ed]) + 1
		extLen := int(httpHead[ed])<<8|int(httpHead[ed+1])
		ed += 2
		for i := 0; i < extLen; i++ {
			extTyp := int(httpHead[ed])<<8|int(httpHead[ed+1])
			len := int(httpHead[ed+2])<<8|int(httpHead[ed+3])
			if extTyp == 0 {
				ed += 7
				IPLen = int(httpHead[ed])<<8|int(httpHead[ed+1])
				ed += 2
				break
			} else {
				ed += len + 4
			}
		}
		if IPLen == -1 {
			return nil, false, "", errors.New("Wrong TLS Version")
		} else {
			fmt.Println(string(httpHead[ed : ed+IPLen])) //debug
			return httpHead[0:allLen+5], true, string(httpHead[ed : ed+IPLen]), nil
		}
	}
}
func httpDirect(conn net.Conn, serverIP, finalIP string) (net.Conn, error) {
	log.Println(serverIP) // 监视

	// 分流策略
	var target string
	target = serverIP

	if target == serverIP {
		targetConn, err := connectTCPServer(conn, serverIP, true)
		return targetConn, err
	} else {
		targetConn, err := connectTCPProxy(conn, serverIP, target, true)
		return targetConn, err
	}
}
func httpBan(conn net.Conn, serverIP, finalIP string) (net.Conn, error) {
	log.Println(serverIP) // 监视

	// 分流策略
	var target string
	if strings.Contains(finalIP, "bilibili") {
		target = IPList[0]
	} else {
		target = serverIP
	}

	if target == serverIP {
		targetConn, err := connectTCPServer(conn, serverIP, true)
		return targetConn, err
	} else {
		targetConn, err := connectTCPProxy(conn, serverIP, target, true)
		return targetConn, err
	}
}
func httpFull(conn net.Conn, serverIP, finalIP string) (net.Conn, error) {
	log.Println(serverIP) // 监视

	// 分流策略
	var target string
	if strings.Contains(finalIP, "bilibili") {
		target = IPList[0]
	} else if strings.Contains(finalIP, "baidu") {
		target = IPList[1]
	} else if strings.Contains(finalIP, "codeforces") {
		target = IPList[2]
	} else if strings.Contains(finalIP, "sjtu") {
		target = IPList[3]
	} else {
		target = serverIP
	}

	if target == serverIP {
		targetConn, err := connectTCPServer(conn, serverIP, true)
		return targetConn, err
	} else {
		targetConn, err := connectTCPProxy(conn, serverIP, target, true)
		return targetConn, err
	}
}