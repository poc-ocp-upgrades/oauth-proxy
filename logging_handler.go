package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

type responseLogger struct {
	w			http.ResponseWriter
	status		int
	size		int
	upstream	string
	authInfo	string
}

func (l *responseLogger) Header() http.Header {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return l.w.Header()
}
func (l *responseLogger) ExtractGAPMetadata() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	upstream := l.w.Header().Get("GAP-Upstream-Address")
	if upstream != "" {
		l.upstream = upstream
		l.w.Header().Del("GAP-Upstream-Address")
	}
	authInfo := l.w.Header().Get("GAP-Auth")
	if authInfo != "" {
		l.authInfo = authInfo
		l.w.Header().Del("GAP-Auth")
	}
}
func (l *responseLogger) Write(b []byte) (int, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if l.status == 0 {
		l.status = http.StatusOK
	}
	l.ExtractGAPMetadata()
	size, err := l.w.Write(b)
	l.size += size
	return size, err
}
func (l *responseLogger) WriteHeader(s int) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	l.ExtractGAPMetadata()
	l.w.WriteHeader(s)
	l.status = s
}
func (l *responseLogger) Status() int {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return l.status
}
func (l *responseLogger) Size() int {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return l.size
}

type loggingHandler struct {
	writer	io.Writer
	handler	http.Handler
	enabled	bool
}

func LoggingHandler(out io.Writer, h http.Handler, v bool) http.Handler {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return loggingHandler{out, h, v}
}
func (h loggingHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	t := time.Now()
	url := *req.URL
	logger := &responseLogger{w: w}
	h.handler.ServeHTTP(logger, req)
	if !h.enabled {
		return
	}
	logLine := buildLogLine(logger.authInfo, logger.upstream, req, url, t, logger.Status(), logger.Size())
	h.writer.Write(logLine)
}
func buildLogLine(username, upstream string, req *http.Request, url url.URL, ts time.Time, status int, size int) []byte {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if username == "" {
		username = "-"
	}
	if upstream == "" {
		upstream = "-"
	}
	if url.User != nil && username == "-" {
		if name := url.User.Username(); name != "" {
			username = name
		}
	}
	client := req.Header.Get("X-Real-IP")
	if client == "" {
		client = req.RemoteAddr
	}
	if c, _, err := net.SplitHostPort(client); err == nil {
		client = c
	}
	duration := float64(time.Now().Sub(ts)) / float64(time.Second)
	logLine := fmt.Sprintf("%s - %s [%s] %s %s %s %q %s %q %d %d %0.3f\n", client, username, ts.Format("02/Jan/2006:15:04:05 -0700"), req.Host, req.Method, upstream, url.RequestURI(), req.Proto, req.UserAgent(), status, size, duration)
	return []byte(logLine)
}
