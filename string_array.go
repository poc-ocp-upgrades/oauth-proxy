package main

import (
	"strings"
)

type StringArray []string

func (a *StringArray) Set(s string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	*a = append(*a, s)
	return nil
}
func (a *StringArray) String() string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return strings.Join(*a, ",")
}
