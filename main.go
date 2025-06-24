package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/volcengine/volcengine-go-sdk/service/dns"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
	"k8s.io/klog/v2"
	"os"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	defaultTTL = 600
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&volcengineDNSProviderSolver{},
	)
}

// volcengineDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type volcengineDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	//client kubernetes.Clientset

	client           *kubernetes.Clientset
	volcengineClient *dns.DNS
}

// volcengineDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type volcengineDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	//APIKeySecretRef v1alpha1.SecretKeySelector `json:"apiKeySecretRef"`

	AccessKey cmmetav1.SecretKeySelector `json:"accessKeySecretRef"`
	SecretKey cmmetav1.SecretKeySelector `json:"secretKeySecretRef"`
	RegionId  string                     `json:"regionId"`
	TTL       *int32                     `json:"ttl"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *volcengineDNSProviderSolver) Name() string {
	return "volcengine"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *volcengineDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("call function Present: namespace=%s, zone=%s, fqdn=%s",
		ch.ResourceNamespace, ch.ResolvedZone, ch.ResolvedFQDN)

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	// do something more useful with the decoded configuration
	fmt.Printf("Decoded configuration %v", cfg)

	accessKey, err := c.loadSecretData(cfg.AccessKey, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	secretKey, err := c.loadSecretData(cfg.SecretKey, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	conf := volcengine.NewConfig().
		WithCredentials(credentials.NewStaticCredentials(string(accessKey), string(secretKey), "")).
		WithRegion(cfg.RegionId)

	sess, err := session.NewSession(conf)
	if err != nil {
		return err
	}
	c.volcengineClient = dns.New(sess)

	zid, err := c.getHostedZone(ch.ResolvedZone)
	if err != nil {
		return fmt.Errorf("volcengine: error getting hosted zones: %v", err)
	}

	//  volcengine sdk list privatezone res zid type is int32, but create record api input req type is int64
	recordReq := c.newTxtRecord(int64(zid), ch.ResolvedZone, ch.ResolvedFQDN, ch.Key, *cfg.TTL)

	_, err = c.volcengineClient.CreateRecord(&recordReq)
	if err != nil {
		return fmt.Errorf("volcengine: error adding domain record: %v", err)
	}

	klog.Infof("Presented txt record %v", ch.ResolvedFQDN)

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *volcengineDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	// add code that deletes a record from the DNS provider's console
	zoneId, err := c.getHostedZone(ch.ResolvedZone)
	if err != nil {
		return fmt.Errorf("volcengine: error getting hosted zone: %v", err)
	}
	records, err := c.findTxtRecord(int64(zoneId), ch.ResolvedZone, ch.ResolvedFQDN)
	if err != nil {
		return fmt.Errorf("volcengine: error finding TXT record: %v", err)
	}

	for _, record := range records {
		if ch.Key == *record.Value {
			request := dns.DeleteRecordInput{}
			request.SetRecordID(*record.RecordID)
			_, err := c.volcengineClient.DeleteRecord(&request)
			if err != nil {
				return fmt.Errorf("volcengine: error deleting TXT record: %v", err)
			}
			klog.Infof("deleted TXT record %v", ch.ResolvedFQDN)
		}
	}
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *volcengineDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	///// UNCOMMENT THE BELOW CODE TO MAKE A KUBERNETES CLIENTSET AVAILABLE TO
	///// YOUR CUSTOM DNS PROVIDER

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	///// END OF CODE TO MAKE KUBERNETES CLIENTSET AVAILABLE
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (*volcengineDNSProviderConfig, error) {
	ttl := int32(defaultTTL)
	cfg := &volcengineDNSProviderConfig{TTL: &ttl}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

// getHostedZone is a helper function that gets the ZID of the hosted zone
// for the given domain name.
func (c *volcengineDNSProviderSolver) getHostedZone(resolvedZone string) (int32, error) {
	request := dns.ListZonesInput{}
	var startPage int32 = 1
	var pageSize int32 = 10
	domains := make(map[string]int32)

	for {
		request.PageNumber = &startPage
		request.PageSize = &pageSize
		response, err := c.volcengineClient.ListZones(&request)
		if err != nil {
			return 0, fmt.Errorf("volcengine: error listing private zones: %v", err)
		}

		for _, domain := range response.Zones {
			domains[*domain.ZoneName] = *domain.ZID
		}

		if startPage**&pageSize >= *response.Total {
			break
		}

		startPage++
	}

	var hostedZone int32
	if zid, exists := domains[util.UnFqdn(resolvedZone)]; exists {
		hostedZone = zid
	} else {
		return 0, fmt.Errorf("zone %s not found in volcengine private zone", resolvedZone)
	}

	return hostedZone, nil

}

// newTxtRecord is a helper function that creates a new TXT record input for
// the given zone, fqdn, and value.
func (c *volcengineDNSProviderSolver) newTxtRecord(zoneId int64, zone, fqdn, value string, ttl int32) dns.CreateRecordInput {
	klog.Infof("Creating TXT record for fqdn: %s , zone: %v", fqdn, zone)
	request := dns.CreateRecordInput{}
	request.SetType("TXT")
	request.SetZID(zoneId)
	request.SetTTL(ttl)
	name := c.extractRecordName(fqdn, zone)
	klog.Infof("Record name: %v", name)
	request.SetHost(name)
	request.SetValue(value)

	return request
}

func (c *volcengineDNSProviderSolver) findTxtRecord(zoneId int64, domain, fqdn string) ([]dns.RecordForListRecordsOutput, error) {
	zoneName := util.UnFqdn(domain)
	request := dns.ListRecordsInput{}
	request.SetZID(zoneId)
	request.SetPageSize(500)

	var records []dns.RecordForListRecordsOutput

	result, err := c.volcengineClient.ListRecords(&request)
	if err != nil {
		return records, fmt.Errorf("volcengine: error describing domain records: %v", err)
	}

	recordName := c.extractRecordName(fqdn, zoneName)
	for _, record := range result.Records {
		if record.Host == &recordName {
			records = append(records, *record)
		}
	}
	return records, nil
}

// extractRecordName is a helper function that extracts the record name from
// the fully qualified domain name.
func (c *volcengineDNSProviderSolver) extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.LastIndex(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}

// loadSecretData is a helper function that loads the data from a Kubernetes
// Secret resource.
func (c *volcengineDNSProviderSolver) loadSecretData(selector cmmetav1.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := c.client.CoreV1().Secrets(ns).Get(context.TODO(), selector.Name, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load secret %q", ns+"/"+selector.Name)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, errors.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}
