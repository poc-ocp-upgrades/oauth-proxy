package main

import (
	"github.com/bmizerany/assert"
	"testing"
)

func TestTemplatesCompile(t *testing.T) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	templates := getTemplates()
	assert.NotEqual(t, templates, nil)
}
