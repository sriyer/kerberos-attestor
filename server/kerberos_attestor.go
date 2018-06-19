package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"sync"

	gokrb_config "github.com/nks5295/gokrb5/config"
	gokrb_creds "github.com/nks5295/gokrb5/credentials"
	gokrb_keytab "github.com/nks5295/gokrb5/keytab"
	gokrb_service "github.com/nks5295/gokrb5/service"

	fqdn "github.com/Showmax/go-fqdn"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/hcl"

	krbc "github.com/spiffe/kerberos-attestor/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
)

const (
	pluginName = "kerberos_attestor"
)

type KrbAttestorPlugin struct {
	realm     string
	krbConfig *gokrb_config.Config
	keytab    gokrb_keytab.Keytab
	spireSPN  string

	mtx *sync.Mutex
}

type KrbAttestorConfig struct {
	KrbRealm      string `hcl:"krb_realm"`
	KrbConfPath   string `hcl:"krb_conf_path"`
	KrbKeytabPath string `hcl:"krb_keytab_path"`
}

func New() *KrbAttestorPlugin {
	return &KrbAttestorPlugin{
		mtx: &sync.Mutex{},
	}
}

func (k *KrbAttestorPlugin) spiffeID(krbCreds gokrb_creds.Credentials) *url.URL {
	spiffePath := path.Join("spire", "agent", pluginName, krbCreds.Domain(), krbCreds.DisplayName())
	id := &url.URL{
		Scheme: "spiffe",
		Host:   strings.ToLower(k.realm),
		Path:   spiffePath,
	}
	return id
}

func (k *KrbAttestorPlugin) Attest(stream nodeattestor.Attest_PluginStream) error {
	var attestedData krbc.KrbAttestedData
	var buf bytes.Buffer

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	buf.Write(req.AttestationData.Data)
	dec := gob.NewDecoder(&buf)
	err = dec.Decode(&attestedData)
	if err != nil {
		return krbc.AttestationStepError("decoding KRB_AP_REQ from attestation data", err)
	}

	valid, creds, err := gokrb_service.ValidateAPREQ(attestedData.KrbAPReq, k.keytab, k.spireSPN, "0", false)
	if err != nil {
		return krbc.AttestationStepError("validating KRB_AP_REQ", err)
	}

	if !valid {
		return krbc.AttestationStepError("validating KRB_AP_REQ", errors.New("failed to validate KRB_AP_REQ"))
	}

	err = stream.Send(&nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: k.spiffeID(creds).String(),
	})
	if err != nil {
		return err
	}

	return nil
}

func (k *KrbAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	resp := &spi.ConfigureResponse{}
	config := &KrbAttestorConfig{}

	hclTree, err := hcl.Parse(req.Configuration)
	if err != nil {
		err := fmt.Errorf("Error parsing Kerberos Attestor configuration: %s", err)
		return resp, err
	}
	err = hcl.DecodeObject(&config, hclTree)
	if err != nil {
		err := fmt.Errorf("Erorr decoding Kerberos Attestor configuration: %s", err)
		return resp, err
	}

	k.mtx.Lock()
	defer k.mtx.Unlock()

	krbCfg, err := gokrb_config.Load(config.KrbConfPath)
	if err != nil {
		err := fmt.Errorf("Error loading Kerberos config: %s", err)
		return resp, err
	}

	krbKt, err := gokrb_keytab.Load(config.KrbKeytabPath)
	if err != nil {
		err := fmt.Errorf("Error loading Kerberos keytab: %s", err)
		return resp, err
	}

	hostname := fqdn.Get()
	if hostname == "unknown" {
		err := fmt.Errorf("Error getting machine FQDN")
		return resp, err
	}
	spireSPN := fmt.Sprintf("%s/%s", krbc.SPIREServiceName, hostname)

	k.realm = config.KrbRealm
	k.krbConfig = krbCfg
	k.keytab = krbKt
	k.spireSPN = spireSPN

	return &spi.ConfigureResponse{}, nil
}

func (k *KrbAttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		Plugins: map[string]plugin.Plugin{
			pluginName: nodeattestor.GRPCPlugin{
				ServerImpl: &nodeattestor.GRPCServer{
					Plugin: New(),
				},
			},
		},
		HandshakeConfig: nodeattestor.Handshake,
		GRPCServer:      plugin.DefaultGRPCServer,
	})
}
