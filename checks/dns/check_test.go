package dns

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const dnsDomainEnv = "HEALTH_GO_DNS_DOMAIN"
const dnsNSServerEnv = "HEALTH_GO_DNS_NSSVR"
const dnsNSPortEnv = "HEALTH_GO_DNS_NSPORT"

func TestNew(t *testing.T) {
	check := New(Config{
		Domain:   getDomain(t),
		NSServer: getNSServer(t),
		NSPort:   getNSPort(t),
	})

	err := check(context.Background())
	require.NoError(t, err)
}

func getDomain(t *testing.T) string {
	t.Helper()

	Domain, ok := os.LookupEnv(dnsDomainEnv)
	require.True(t, ok)

	return Domain
}

func getNSServer(t *testing.T) string {
	t.Helper()

	NSServer, ok := os.LookupEnv(dnsNSServerEnv)
	require.True(t, ok)

	return NSServer
}

func getNSPort(t *testing.T) string {
	t.Helper()

	NSPort, ok := os.LookupEnv(dnsNSPortEnv)
	require.True(t, ok)

	return NSPort
}
