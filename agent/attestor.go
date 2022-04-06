package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	gokrbclient "gopkg.in/jcmturner/gokrb5.v7/client"
	gokrbconfig "gopkg.in/jcmturner/gokrb5.v7/config"
	gokrbcrypto "gopkg.in/jcmturner/gokrb5.v7/crypto"
	gokrbkeytab "gopkg.in/jcmturner/gokrb5.v7/keytab"
	gokrbmsgs "gopkg.in/jcmturner/gokrb5.v7/messages"
	gokrbtypes "gopkg.in/jcmturner/gokrb5.v7/types"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"github.com/spiffe/spire-plugin-sdk/pluginmain"

	"github.com/spiffe/kerberos-attestor/common"
)

type Config struct {
	KrbRealm      string `hcl:"krb_realm"`
	KrbConfPath   string `hcl:"krb_conf_path"`
	KrbKeytabPath string `hcl:"krb_keytab_path"`
	Spn           string `hcl:"spn"`
}

type Plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer
	mu        sync.Mutex
	log       hclog.Logger
	realm     string
	krbConfig *gokrbconfig.Config
	keytab    *gokrbkeytab.Keytab
	username  string
	spn       string
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) (err error) {
	client := gokrbclient.NewClientWithKeytab(p.username, p.realm, p.keytab, p.krbConfig)
	defer client.Destroy()

	// Step 1: Log into the KDC and fetch TGT (Ticket-Granting Ticket) from KDC AS (Authentication Service)
	if err := client.Login(); err != nil {
		return common.PluginErr.New("[AS_REQ] logging in: %v", err)
	}

	// Step 2: Use the TGT to fetch Service Ticket of SPIRE server from KDC TGS (Ticket-Granting Service)
	serviceTkt, encryptionKey, err := client.GetServiceTicket(p.spn)
	if err != nil {
		return common.PluginErr.New("[TGS_REQ] requesting service ticket: %v", err)
	}

	// Step 3: Create an authenticator including client's info and timestamp
	authenticator, err := gokrbtypes.NewAuthenticator(client.Credentials.Domain(), client.Credentials.CName())
	if err != nil {
		return common.PluginErr.New("[KRB_AP_REQ] building Kerberos authenticator: %v", err)
	}

	encryptionType, err := gokrbcrypto.GetEtype(encryptionKey.KeyType)
	if err != nil {
		return common.PluginErr.New("[KRB_AP_REQ] getting encryption key type: %v", err)
	}

	err = authenticator.GenerateSeqNumberAndSubKey(encryptionType.GetETypeID(), encryptionType.GetKeyByteSize())
	if err != nil {
		return common.PluginErr.New("[KRB_AP_REQ] generating authenticator sequence number and subkey: %v", err)
	}

	// Step 4: Create an AP (Authentication Protocol) request which will be decrypted by SPIRE server's kerberos
	// attestor
	krbAPReq, err := gokrbmsgs.NewAPReq(serviceTkt, encryptionKey, authenticator)
	if err != nil {
		return common.PluginErr.New("[KRB_AP_REQ] building KRB_AP_REQ: %v", err)
	}

	attestedData := common.KrbAttestedData{
		KrbAPReq: krbAPReq,
	}

	data, err := json.Marshal(attestedData)
	if err != nil {
		return common.PluginErr.New("marshaling KRB_AP_REQ for transport: %v", err)
	}

	resp := &nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: data,
		},
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	return nil
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, common.PluginErr.New("unable to decode configuration: %v", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	krbCfg, err := gokrbconfig.Load(config.KrbConfPath)
	if err != nil {
		return nil, common.PluginErr.New("error loading Kerberos config: %v", err)
	}

	krbKt, err := gokrbkeytab.Load(config.KrbKeytabPath)
	if err != nil {
		return nil, common.PluginErr.New("error loading Kerberos keytab: %v", err)
	}

	p.realm = config.KrbRealm
	p.krbConfig = krbCfg
	p.keytab = krbKt
	p.username = getPrincipalName(krbKt)
	p.spn = config.Spn

	return &configv1.ConfigureResponse{}, nil
}

func getPrincipalName(kt *gokrbkeytab.Keytab) string {
	if len(kt.Entries) == 0 {
		return ""
	}
	principal := kt.Entries[0].Principal
	return strings.Join(principal.Components, "/")
}

func main() {
	p := New()
	pluginmain.Serve(nodeattestorv1.NodeAttestorPluginServer(p), configv1.ConfigServiceServer(p))
}
