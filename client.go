package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"strconv"
	"errors"
)
var IPList = func() []string {
	f, _ := ioutil.ReadFile("IPList")
	return strings.Split(string(f), ",")
} ()
var port, socksType, httpType, TLSType string
func checkAuth(conn net.Conn) error {
	buf := make([]byte, 258)
	// 读取客户端的请求认证信息
	_, err := io.ReadFull(conn, buf[:2])
	if err != nil {
		return err
	}
	// 只处理Socket5协议
	if buf[0] != 0x05 {
		return errors.New("Invalid SOCKS version")
	}
	// 只支持无需认证的方式
	methodLen := (int)(buf[1])
	_, err = io.ReadFull(conn, buf[:methodLen])
	if err != nil {
		return err
	}
	var isAuth bool = false
	for _, val := range buf[:methodLen] {
		if val == 0x00 {
			isAuth = true
			break
		}
	}
	if isAuth == false {
		conn.Write([]byte{0x05, 0xFF})
		return errors.New("Unsupported Auth")
	} else {
		conn.Write([]byte{0x05, 0x00})
		return nil
	}
}
func handshakeTCP(targetConn net.Conn) error {
	buf := make([]byte, 5)
	targetConn.Write([]byte{0x05, 0x01, 0x00})
	_, err := io.ReadFull(targetConn, buf[:2])
	if err != nil {
		return errors.New("Read Error")
	}
	if buf[1] == 0xFF {
		return errors.New("Auth Failed")
	}
	return nil
}
func connectTCPProxy(conn net.Conn, serverIP, target string, isWritten bool) (net.Conn, error) {
	errbuf := []byte{0x05, 0x00}

	// 连接与异常处理
	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		var code byte = 0x01
		str := err.Error()
		if strings.Contains(str, "no route") {
			code = 0x03
		} else if strings.Contains(str, "lookup") {
			code = 0x04
		} else if strings.Contains(str, "network is unreachable") {
			code = 0x03
		} else if strings.Contains(str, "name resolution") {
			code = 0x04
		} else if strings.Contains(str, "refused") {
			code = 0x05
		}
		errbuf[1] = code
		conn.Write(errbuf)
		return nil, err
	}
	err = handshakeTCP(targetConn)
	if err != nil {
		var code byte = 0x01
		str := err.Error()
		if strings.Contains(str, "Auth") {
			code = 0x02
		}
		errbuf[1] = code
		conn.Write(errbuf)
		return nil, err
	}
	IP_str, port_str, _ := net.SplitHostPort(serverIP)
	retIP := net.ParseIP(IP_str) // 无法解析 http！！！
	port, _ := strconv.Atoi(port_str)
	var retIPtype byte
	if retIP == nil {
		retIPtype = 0x03
	} else if len(retIP) == 4 {
		retIPtype = 0x01
	} else {
		retIPtype = 0x04
	}
	ret := []byte{0x05, 0x01, 0x00, retIPtype}
	if retIPtype == 0x03 {
		ret = append(ret, byte(len(IP_str)))
		ret = append(ret, IP_str...)
	} else {
		ret = append(ret, retIP...)
	}
	ret = append(ret, (byte)(port>>8), (byte)(port&255))
	targetConn.Write(ret)

	// 不需要返回包，等待下一级发包
	if isWritten {
		buf := make([]byte, 258)
		_, err = io.ReadFull(targetConn, buf[:4])
		if err != nil {
			return nil, err
		}
		if buf[3] == 0x01 {
			_, err = io.ReadFull(targetConn, buf[:6])
			if err != nil {
				return nil, err
			}
		} else if buf[3] == 0x03 {
			_, err = io.ReadFull(targetConn, buf[:1])
			if err != nil {
				return nil, err
			}
			addrLen := int(buf[0])
			_, err = io.ReadFull(targetConn, buf[:addrLen+2])
			if err != nil {
				return nil, err
			}
		} else if buf[3] == 0x04 {
			_, err = io.ReadFull(targetConn, buf[:18])
			if err != nil {
				return nil, err
			}
		}
	}
	return targetConn, nil
}
func connectTCPServer(conn net.Conn, target string, isWritten bool) (net.Conn, error) {
	errbuf := []byte{0x05, 0x00}

	// 连接与异常处理
	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		var code byte = 0x00
		str := err.Error()
		if strings.Contains(str, "no route") {
			code = 0x03
		} else if strings.Contains(str, "lookup") {
			code = 0x04
		} else if strings.Contains(str, "network is unreachable") {
			code = 0x03
		} else if strings.Contains(str, "name resolution") {
			code = 0x04
		} else if strings.Contains(str, "refused") {
			code = 0x05
		}
		errbuf[1] = code
		conn.Write(errbuf)
		return nil, err
	}
	// 分配IP与端口，返回包
	if isWritten {
		return targetConn, nil
	}
	IP_str, port_str, _ := net.SplitHostPort(targetConn.LocalAddr().String())
	retIP := net.ParseIP(IP_str)
	port, _ := strconv.Atoi(port_str)
	var retIPtype byte
	if len(retIP) == 4 {
		retIPtype = 0x01
	} else {
		retIPtype = 0x04
	}
	ret := append([]byte{0x05, 0x00, 0x00, retIPtype}, retIP...)
	ret = append(ret, (byte)(port>>8), (byte)(port&255))
	//fmt.Println(ret) // debug
	conn.Write(ret)
	return targetConn, nil
}
func handleUDP(serverConn *net.UDPConn, localAddr net.Addr) error {
	localBuf := make([]byte, 258)
	remoteBuf := make([]byte, 258)
	// 预处理表头
	IP_str, port_str, _ := net.SplitHostPort(localAddr.String())
	retIP := net.ParseIP(IP_str)
	port, _ := strconv.Atoi(port_str)
	var retIPtype byte
	if len(retIP) == 4 {
		retIPtype = 0x01
	} else {
		retIPtype = 0x04
	}
	ret := append([]byte{0x05, 0x00, 0x00, retIPtype}, retIP...)
	ret = append(ret, (byte)(port>>8), (byte)(port&255))
	//fmt.Println(localAddr) //debug
	for {
		// 解析目标地址
		n, remoteAddr, err := serverConn.ReadFromUDP(localBuf)
		if localBuf[0] != 0 || localBuf[1] != 0 {
			return errors.New("UDP: Local RSV Error")
		}
		if err != nil {
			return err
		}
		// 解析Data位置
		remoteConn, err := net.ListenUDP("udp", remoteAddr)
		if err != nil {
			return err
		}
		var dataStart int
		if localBuf[3] == 0x01 {
			dataStart = 10
		} else if localBuf[3] == 0x03 {
			dataStart = (int)(localBuf[4]) + 7
		} else if localBuf[3] == 0x04 {
			dataStart = 22
		}
		// 将data用UDP传给目标
		_, err = remoteConn.WriteToUDP(localBuf[dataStart:n], remoteAddr)
		if err != nil {
			return err
		}
		// 接受目标的返回data
		n, _, err = remoteConn.ReadFromUDP(remoteBuf)
		if remoteBuf[0] != 0 || remoteBuf[1] != 0 {
			return errors.New("UDP: Remote RSV Error")
		}
		if err != nil {
			return err
		}
		if remoteBuf[3] == 0x01 {
			dataStart = 10
		} else if remoteBuf[3] == 0x03 {
			dataStart = (int)(remoteBuf[4]) + 7
		} else if remoteBuf[3] == 0x04 {
			dataStart = 22
		}
		// 封装表头，发回
		localUDPAddr, err := net.ResolveUDPAddr("udp",localAddr.String())
		if err != nil {
			return err
		}
		_, err = serverConn.WriteToUDP(append(ret, remoteBuf[dataStart:n]...), localUDPAddr)
		if err != nil {
			return err
		}
		remoteConn.Close()
	}
}
func connectUDP(conn net.Conn) error {
	// 分配地址与端口
	serverConn, err := net.ListenUDP("udp", nil)
    if err != nil {
        return err
    }
	serverAddr := serverConn.LocalAddr()
	//fmt.Println(serverAddr) //debug
	IP_str, port_str, _ := net.SplitHostPort(serverAddr.String())
	retIP := net.ParseIP(IP_str)
	port, _ := strconv.Atoi(port_str)
	var retIPtype byte
	if len(retIP) == 4 {
		retIPtype = 0x01
	} else {
		retIPtype = 0x04
	}
	ret := append([]byte{0x05, 0x00, 0x00, retIPtype}, retIP...)
	ret = append(ret, (byte)(port>>8), (byte)(port&255))
	//fmt.Println(ret) //debug
	conn.Write(ret)
	err = handleUDP(serverConn, conn.RemoteAddr())
	if err != nil {
		return err
	}
	return nil
}
func getTarget(conn net.Conn) (string, byte, error) {
	buf := make([]byte, 258)
	errbuf := []byte{0x05, 0x00}
	_, err := io.ReadFull(conn, buf[:1])
	if err != nil {
		return "", 0x00, errors.New("Read Error")
	}
	IPtype := buf[0]
	var target string
	if IPtype == 0x01 {
		// 使用IPv4地址
		_, err = io.ReadFull(conn, buf[:6])
		if err != nil {
			return "", 0x00, errors.New("Read Error")
		}
		targetAddr := net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
		targetPort := fmt.Sprintf("%d", int(buf[4])<<8|int(buf[5]))
		target = net.JoinHostPort(targetAddr, targetPort)
	} else if IPtype == 0x03 {
		// 使用域名地址
		_, err = io.ReadFull(conn, buf[:1])
		if err != nil {
			return "", 0x00, errors.New("Read Error")
		}
		addrLen := int(buf[0])
		_, err = io.ReadFull(conn, buf[:addrLen+2])
		if err != nil {
			return "", 0x00, errors.New("Read Error")
		}
		targetAddr := string(buf[:addrLen])
		targetPort := fmt.Sprintf("%d", int(buf[addrLen])<<8|int(buf[addrLen+1]))
		target = net.JoinHostPort(targetAddr, targetPort)
	} else if IPtype == 0x04 {
		// 使用IPv6地址
		_, err = io.ReadFull(conn, buf[:18])
		if err != nil {
			return "", 0x00, errors.New("Read Error")
		}
		targetAddr := net.IP(buf[:16]).String()
		targetPort := fmt.Sprintf("%d", int(buf[16])<<8|int(buf[17]))
		target = net.JoinHostPort(targetAddr, targetPort)
	} else {
		errbuf[1] = 0x08
		conn.Write(errbuf)
		return "", 0x00, errors.New("Invalid address type")
	}
	return target, IPtype, nil
}
func handleQuery(conn net.Conn) error {
	// 读取客户端发送的请求详细信息
	buf := make([]byte, 258)
	errbuf := []byte{0x05, 0x00}
	// 表头
	_, err := io.ReadFull(conn, buf[:3])
	if err != nil {
		return errors.New("Read Error")
	}
	if buf[0] != 0x05 || buf[2] != 0x00 {
		return errors.New("VER/RSV Error")
	}
	// 解析请求信息，目前只支持 Connect 与 UDP
	if buf[1] == 0x01 {
		serverIP, IPtype, err := getTarget(conn)
		if err != nil {
			return err
		}
		var targetConn net.Conn
		if IPtype == 0x03 {
			targetConn, err = socksDirect(conn, serverIP, IPtype, false)
			if err != nil {
				return err
			}
			targetConn.Close()
			//httpHead, _, _, _ := readHttpHead(conn) //debug
			httpHead, isHttps, finalIP, err := readHttpHead(conn)
			fmt.Println(isHttps)
			if err != nil {
				return err
			}
			if isHttps {
				if TLSType == "none" {
					targetConn, err = resolveSocks(conn, serverIP, IPtype, socksType, true)
					if err != nil {
						return err
					}
				} else {
					targetConn, err = resolveTLS(conn, serverIP, finalIP, TLSType)
					if err != nil {
						return err
					}
				}
			} else {
				if httpType == "none" {
					targetConn, err = resolveSocks(conn, serverIP, IPtype, socksType, true)
					if err != nil {
						return err
					}
				} else {
					targetConn, err = resolveHttp(conn, serverIP, finalIP, httpType)
					if err != nil {
						return err
					}
				}
			}
			targetConn.Write(httpHead)
			// fmt.Println(httpHead)
		} else {
			targetConn, err = resolveSocks(conn, serverIP, IPtype, socksType, false)
			if err != nil {
				return err
			}
		}
		

		go func() {
			defer conn.Close()
			defer targetConn.Close()
			io.Copy(conn, targetConn)
		} ()
		go func() {
			defer conn.Close()
			defer targetConn.Close()
			io.Copy(targetConn, conn)
		} ()
		return nil
	} else if buf[1] == 0x03 {
		err := connectUDP(conn)
		if err != nil {
			conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
			return err
		}
		conn.Close()
		return nil
	} else {
		errbuf[1] = 0x07
		conn.Write(errbuf)
		return errors.New("Unsupported command")
	}
}
func handleClient(conn net.Conn) {
	err := checkAuth(conn)
	if err != nil {
		log.Println(err)
		return 
	}
	err = handleQuery(conn)
	if err != nil {
		log.Println(err)
		return
	}
}
func main() {
	// 监听指定的端口
	var port string
	flag.StringVar(&port, "port", "8080", "端口")
	flag.StringVar(&socksType, "socks", "direct", "socks分流类型")
	flag.StringVar(&httpType, "http", "none", "http分流类型")
	flag.StringVar(&TLSType, "TLS", "none", "TLS分流类型")
	flag.Parse()
	l, err := net.Listen("tcp", ":" + port)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	log.Println("SOCKS5 proxy client is running on port " + port)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleClient(conn)
	}
}