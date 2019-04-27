package openshift

import (
	"flag"
	"time"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	authorizationclient "k8s.io/client-go/kubernetes/typed/authorization/v1beta1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type DelegatingAuthorizationOptions struct {
	RemoteKubeConfigFile	string
	AllowCacheTTL		time.Duration
	DenyCacheTTL		time.Duration
}

func NewDelegatingAuthorizationOptions() *DelegatingAuthorizationOptions {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return &DelegatingAuthorizationOptions{AllowCacheTTL: 10 * time.Second, DenyCacheTTL: 10 * time.Second}
}
func (s *DelegatingAuthorizationOptions) Validate() []error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	allErrors := []error{}
	return allErrors
}
func (s *DelegatingAuthorizationOptions) AddFlags(fs *flag.FlagSet) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	fs.StringVar(&s.RemoteKubeConfigFile, "authorization-kubeconfig", s.RemoteKubeConfigFile, ""+"kubeconfig file pointing at the 'core' kubernetes server with enough rights to create "+" subjectaccessreviews.authorization.k8s.io.")
	fs.DurationVar(&s.AllowCacheTTL, "authorization-webhook-cache-authorized-ttl", s.AllowCacheTTL, "The duration to cache 'authorized' responses from the webhook authorizer.")
	fs.DurationVar(&s.DenyCacheTTL, "authorization-webhook-cache-unauthorized-ttl", s.DenyCacheTTL, "The duration to cache 'unauthorized' responses from the webhook authorizer.")
}
func (s *DelegatingAuthorizationOptions) ToAuthorizationConfig() (authorizerfactory.DelegatingAuthorizerConfig, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	sarClient, err := s.newSubjectAccessReview()
	if err != nil {
		return authorizerfactory.DelegatingAuthorizerConfig{}, err
	}
	ret := authorizerfactory.DelegatingAuthorizerConfig{SubjectAccessReviewClient: sarClient, AllowCacheTTL: s.AllowCacheTTL, DenyCacheTTL: s.DenyCacheTTL}
	return ret, nil
}
func (s *DelegatingAuthorizationOptions) newSubjectAccessReview() (authorizationclient.SubjectAccessReviewInterface, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
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
	client, err := authorizationclient.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}
	return client.SubjectAccessReviews(), nil
}
