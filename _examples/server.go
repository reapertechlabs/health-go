package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/reapertechlabs/health-go/v4"
	healthDNS "github.com/reapertechlabs/health-go/v4/checks/dns"
	healthHttp "github.com/reapertechlabs/health-go/v4/checks/http"
	healthMySql "github.com/reapertechlabs/health-go/v4/checks/mysql"
	healthPg "github.com/reapertechlabs/health-go/v4/checks/postgres"
)

func main() {
	h, _ := health.New()
	// custom health check example (fail)
	h.Register(health.Config{
		Name:      "some-custom-check-fail",
		Timeout:   time.Second * 5,
		SkipOnErr: true,
		Check:     func(context.Context) error { return errors.New("failed during custom health check") },
	})

	// custom health check example (success)
	h.Register(health.Config{
		Name:  "some-custom-check-success",
		Check: func(context.Context) error { return nil },
	})

	// http health check example
	h.Register(health.Config{
		Name:      "http-check",
		Timeout:   time.Second * 5,
		SkipOnErr: true,
		Check: healthHttp.New(healthHttp.Config{
			URL: `https://example.com`,
		}),
	})

	// http health check example
	h.Register(health.Config{
		Name:      "dns-check",
		Timeout:   time.Second * 5,
		SkipOnErr: true,
		Check: healthDNS.New(healthDNS.Config{
			Domain:   `example.network`,
			NSServer: `10.88.0.2`,
			NSPort:   `53`,
			FQDN:     "ns1.example.network",
		}),
	})

	// postgres health check example
	h.Register(health.Config{
		Name:      "postgres-check",
		Timeout:   time.Second * 5,
		SkipOnErr: true,
		Check: healthPg.New(healthPg.Config{
			DSN: `postgres://test:test@0.0.0.0:32783/test?sslmode=disable`,
		}),
	})

	// mysql health check example
	h.Register(health.Config{
		Name:      "mysql-check",
		Timeout:   time.Second * 5,
		SkipOnErr: true,
		Check: healthMySql.New(healthMySql.Config{
			DSN: `test:test@tcp(0.0.0.0:32778)/test?charset=utf8`,
		}),
	})

	// rabbitmq aliveness test example.
	// Use it if your app has access to RabbitMQ management API.
	// This endpoint declares a test queue, then publishes and consumes a message. Intended for use by monitoring tools. If everything is working correctly, will return HTTP status 200.
	// As the default virtual host is called "/", this will need to be encoded as "%2f".
	h.Register(health.Config{
		Name:      "rabbit-aliveness-check",
		Timeout:   time.Second * 5,
		SkipOnErr: true,
		Check: healthHttp.New(healthHttp.Config{
			URL: `https://guest:guest@0.0.0.0:32780/api/aliveness-test/%2f`,
		}),
	})

	http.Handle("/status", h.Handler())
	http.ListenAndServe(":3000", nil)
}
