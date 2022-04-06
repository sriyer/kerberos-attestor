package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"

	gokrbconfig "gopkg.in/jcmturner/gokrb5.v7/config"
	gokrbcreds "gopkg.in/jcmturner/gokrb5.v7/credentials"
	gokrbkeytab "gopkg.in/jcmturner/gokrb5.v7/keytab"
	gokrbservice "gopkg.in/jcmturner/gokrb5.v7/service"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"github.com/spiffe/spire-plugin-sdk/pluginmain"

	"github.com/spiffe/kerberos-attestor/common"
)

const (
	defaultSpiffeScheme = "spiffe"
)

type Config struct {
	KrbRealm      string `hcl:"krb_realm"`
	KrbConfPath   string `hcl:"krb_conf_path"`
	KrbKeytabPath string `hcl:"krb_keytab_path"`
}

type Plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer
	mu          sync.Mutex
	log         hclog.Logger
	realm       string
	krbConfig   *gokrbconfig.Config
	keytab      *gokrbkeytab.Keytab
	trustDomain string
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) spiffeID(krbCreds *gokrbcreds.Credentials) *url.URL {
	spiffePath := path.Join("spire", "agent", common.PluginName, krbCreds.Domain(), krbCreds.DisplayName())
	id := &url.URL{
		Scheme: defaultSpiffeScheme,
		Host:   p.trustDomain,
		Path:   spiffePath,
	}
	return id
}

func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	attestedData := new(common.KrbAttestedData)
	if err := json.Unmarshal(req.GetPayload(), attestedData); err != nil {
		return common.PluginErr.New("unmarshaling KRB_AP_REQ from attestation data: %v", err)
	}

	// Verify the AP (Authentication Protocol) request from SPIRE agent
	s := gokrbservice.NewSettings(p.keytab)
	valid, creds, err := gokrbservice.VerifyAPREQ(attestedData.KrbAPReq, s)
	if err != nil {
		return common.PluginErr.New("validating KRB_AP_REQ: %v", err)
	}

	if !valid {
		return common.PluginErr.New("failed to validate KRB_AP_REQ")
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       p.spiffeID(creds).String(),
				SelectorValues: buildSelectors(creds.CName().PrincipalNameString()),
			},
		},
	})
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, common.PluginErr.New("unable to decode configuration: %v", err)
	}

	if req.GetCoreConfiguration() == nil {
		return nil, common.PluginErr.New("global configuration is required")
	}

	if req.GetCoreConfiguration().GetTrustDomain() == "" {
		return nil, common.PluginErr.New("trust_domain is required")
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
	p.trustDomain = req.GetCoreConfiguration().GetTrustDomain()

	return &configv1.ConfigureResponse{}, nil
}

func buildSelectors(principalName string) []string {

	return []string{fmt.Sprintf("pn:%s", principalName)}

}

func main() {
	p := New()
	pluginmain.Serve(nodeattestorv1.NodeAttestorPluginServer(p), configv1.ConfigServiceServer(p))

}
