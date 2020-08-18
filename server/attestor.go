package main

import (
	"context"
	"encoding/json"
	"net/url"
	"path"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	spc "github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	gokrbconfig "gopkg.in/jcmturner/gokrb5.v7/config"
	gokrbcreds "gopkg.in/jcmturner/gokrb5.v7/credentials"
	gokrbkeytab "gopkg.in/jcmturner/gokrb5.v7/keytab"
	gokrbservice "gopkg.in/jcmturner/gokrb5.v7/service"

	"github.com/yangmarcyang/kerberos-attestor/common"
)

const (
	defaultSpiffeScheme = "spiffe"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(common.PluginName, nodeattestor.PluginServer(p))
}

type Config struct {
	KrbRealm      string `hcl:"krb_realm"`
	KrbConfPath   string `hcl:"krb_conf_path"`
	KrbKeytabPath string `hcl:"krb_keytab_path"`
}

type Plugin struct {
	mu          sync.Mutex
	log         hclog.Logger
	realm       string
	krbConfig   *gokrbconfig.Config
	keytab      *gokrbkeytab.Keytab
	trustDomain string
}

var _ catalog.NeedsLogger = (*Plugin)(nil)

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

func (p *Plugin) Attest(stream nodeattestor.NodeAttestor_AttestServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	attestedData := new(common.KrbAttestedData)
	if err := json.Unmarshal(req.AttestationData.Data, attestedData); err != nil {
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

	return stream.Send(&nodeattestor.AttestResponse{
		AgentId:   p.spiffeID(creds).String(),
		Selectors: buildSelectors(creds.CName().PrincipalNameString()),
	})
}

func (p *Plugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, common.PluginErr.New("unable to decode configuration: %v", err)
	}

	if req.GlobalConfig == nil {
		return nil, common.PluginErr.New("global configuration is required")
	}

	if req.GlobalConfig.TrustDomain == "" {
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
	p.trustDomain = req.GlobalConfig.TrustDomain

	return &spi.ConfigureResponse{}, nil
}

func (p *Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func buildSelectors(principalName string) []*spc.Selector {
	selectors := []*spc.Selector{}

	selectors = append(selectors, &spc.Selector{
		Type: common.PluginName, Value: "pn:" + principalName,
	})

	return selectors
}

func main() {
	catalog.PluginMain(BuiltIn())
}
