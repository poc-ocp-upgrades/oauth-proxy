package providers

import (
	"testing"
	"time"
	"github.com/bmizerany/assert"
)

func TestRefresh(t *testing.T) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	p := &ProviderData{}
	refreshed, err := p.RefreshSessionIfNeeded(&SessionState{ExpiresOn: time.Now().Add(time.Duration(-11) * time.Minute)})
	assert.Equal(t, false, refreshed)
	assert.Equal(t, nil, err)
}
