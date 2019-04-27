package providers

import (
	"net/url"
)

type ProviderData struct {
	ProviderName		string
	ClientID		string
	ClientSecret		string
	ConfigLoginURL		*url.URL
	ConfigRedeemURL		*url.URL
	ValidateURL		*url.URL
	ProfileURL		*url.URL
	ProtectedResource	*url.URL
	Scope			string
	ApprovalPrompt		string
}

func (p *ProviderData) Data() *ProviderData {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return p
}
