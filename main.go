package main

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"io"
)

type VPN struct {
	Country string
	Host    string
	Config  []byte
}

func main() {
	fmt.Println("Fetching vpns . . .")
	resp, err := http.Get("http://www.vpngate.net/api/iphone/")
	if err != nil {
		fmt.Println("Cannot fetch:", err)
		return
	}
	defer resp.Body.Close()
	rdr := csv.NewReader(resp.Body)
	rdr.Comment = '*'
	for {
		r, err := rdr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("csv read error:", err)
			continue
		}
		cfg, err := base64.StdEncoding.DecodeString(r[14])
		if err != nil {
			fmt.Println("Decoding error:", err)
			continue
		}
		if checkMalicious(cfg) {
			fmt.Printf("Possible malicious script in Host: %s\n", r[0])
			continue
		}
		v := VPN{
			Country: r[5],
			Host:    r[0],
			Config:  cfg,
		}
		f, err := os.Create(v.Country + "-" + v.Host)
		if err != nil {
			fmt.Println("Cannot create save file:", err)
		}
		f.Write(v.Config)
	}
	fmt.Println("All files written... exiting")
}

func checkMalicious(cfg []byte) bool {
	if bytes.Contains(cfg, []byte("/bin/bash -c")) {
		return true
	}
	if bytes.Contains(cfg, []byte("System32\\")) {
		return true
	}
	if !bytes.Contains(cfg, []byte("cipher ")) {
		return true
	}
	return false
}
