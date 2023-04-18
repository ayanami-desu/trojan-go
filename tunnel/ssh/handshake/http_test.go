package handshake

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/p4gefau1t/trojan-go/common"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
)

func TestHttp(t *testing.T) {
	p := common.PickPort("tcp", "127.0.0.1")
	port := strconv.Itoa(p)
	go listenHttp(port)
	sendHttp(port)
	sendBytes(port)
}
func sendHttp(port string) {
	bodyBuf := io.NopCloser(new(bytes.Buffer))
	conn, _ := net.Dial("tcp", "127.0.0.1:"+port)
	req := &http.Request{
		Host:   "www.apple.com.sg",
		Method: "POST",
		Body:   bodyBuf,
		URL: &url.URL{
			Scheme: "http",
			Host:   "www.apple.com.sg",
			Path:   "/file?token=public_key",
		},
		ProtoMajor: 1,
		Header:     make(http.Header),
	}
	req.Write(conn)
	fmt.Printf("request over\n")
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, req)
	if err != nil {
		panic(err)
	}
	length := resp.ContentLength
	fmt.Println(length)
	bb := make([]byte, length)
	io.ReadFull(resp.Body, bb)
	fmt.Println(string(bb))
	conn.Close()
}
func listenHttp(port string) {
	l, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		panic(err)
	}
	for {
		conn, _ := l.Accept()
		r := bufio.NewReader(conn)
		req, err := http.ReadRequest(r)
		if err != nil {
			fmt.Printf("not a http request\n")
			conn.Close()
			return
		}
		fmt.Printf("Host: %v; Url: %v\n", req.Host, req.URL)
		data := []byte("hello\r\n")
		resp := &http.Response{
			StatusCode:    200,
			Header:        make(http.Header),
			ProtoMajor:    1,
			ProtoMinor:    1,
			Body:          io.NopCloser(bytes.NewReader(data)),
			ContentLength: int64(len(data)),
		}
		err = resp.Write(conn)
		if err != nil {
			panic(err)
		}
		//conn.Close()
	}
}

func sendBytes(port string) {
	conn, _ := net.Dial("tcp", "127.0.0.1:"+port)
	conn.Write([]byte("abc\r\n"))
	b := make([]byte, 3)
	conn.Read(b)
}
