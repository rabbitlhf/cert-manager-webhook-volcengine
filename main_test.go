package main

import (
	"os"
	"testing"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.
	//

	// Uncomment the below fixture when implementing your custom DNS provider
	//fixture := acmetest.NewFixture(&volcengineDNSProviderSolver{},
	//	acmetest.SetResolvedZone(zone),
	//	acmetest.SetAllowAmbientCredentials(false),
	//	acmetest.SetManifestPath("testdata/my-custom-solver"),
	//	acmetest.SetBinariesPath("_test/kubebuilder/bin"),
	//)
	fixture := acmetest.NewFixture(&volcengineDNSProviderSolver{},
		acmetest.SetResolvedZone(zone),
		//acmetest.SetResolvedFQDN()
		acmetest.SetManifestPath("testdata/volcengine-solver"),
		acmetest.SetDNSServer("127.0.0.1:59351"),
		acmetest.SetUseAuthoritative(false),
	)
	//need to uncomment and  RunConformance delete runBasic and runExtended once https://github.com/cert-manager/cert-manager/pull/4835 is merged
	//fixture.RunConformance(t)
	fixture.RunBasic(t)
	fixture.RunExtended(t)

}
