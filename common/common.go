package common

import (
	"github.com/zeebo/errs"
	"gopkg.in/jcmturner/gokrb5.v7/messages"
)

const (
	PluginName = "kerberos"
)

var (
	PluginErr = errs.Class(PluginName)
)

type KrbAttestedData struct {
	KrbAPReq messages.APReq
}
