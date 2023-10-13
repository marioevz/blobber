package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/marioevz/blobber"
	"github.com/marioevz/blobber/config"
	"github.com/marioevz/blobber/slot_actions"
	"github.com/marioevz/eth-clients/clients"
	beacon_client "github.com/marioevz/eth-clients/clients/beacon"
	"github.com/sirupsen/logrus"
)

type Logger struct{}

func (l *Logger) Logf(msg string, args ...interface{}) {
	logrus.Infof(msg, args...)
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join(*i, ",")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func fatalf(format string, args ...interface{}) {
	fatal(fmt.Errorf(format, args...))
}

func fatal(err error) {
	flag.CommandLine.Usage()
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	var (
		clEndpoints              arrayFlags
		externalIP               string
		hostIP                   string
		clientInitTimeoutSeconds int
		logLevel                 string
		validatorKeyFilePath     string
		slotActionJson           string
		slotActionFrequency      int
		validatorProxyPortStart  int
		maxDevP2PSessionReuses   int
	)

	flag.Var(
		&clEndpoints,
		"cl",
		"Consensus layer client endpoint",
	)
	flag.StringVar(
		&externalIP,
		"external-ip",
		"127.0.0.1",
		"External IP address of the blobber",
	)
	flag.StringVar(
		&hostIP,
		"host-ip",
		"0.0.0.0",
		"Host IP address to listen on",
	)
	flag.StringVar(
		&validatorKeyFilePath,
		"validator-key-file",
		"",
		"Path to validator key file: List of validator keys, one per line in hex format",
	)
	flag.IntVar(
		&clientInitTimeoutSeconds,
		"client-init-timeout",
		60,
		"clients initialization wait timeout in seconds",
	)
	flag.IntVar(
		&validatorProxyPortStart,
		"validator-proxy-port-start",
		20_000,
		"Port number to start validator proxy listening ports from. For each beacon node added, there will be one extra port used.",
	)
	flag.StringVar(
		&slotActionJson,
		"slot-action",
		"",
		"Description of the slot action to execute in JSON formatted string. See slot_actions.go for examples.",
	)
	flag.IntVar(
		&slotActionFrequency,
		"slot-action-frequency",
		1,
		"Frequency of slot actions in slots. 1 means execute every slot, 2 means execute every other slot, etc.",
	)
	flag.IntVar(
		&maxDevP2PSessionReuses,
		"max-dev-p2p-session-reuses",
		0,
		"Maximum number of times to reuse a DevP2P session, which results in a new PeerID. 0 means always use the same session.",
	)
	flag.StringVar(
		&logLevel,
		"log-level",
		"info",
		"Sets the log level (trace, debug, info, warn, error, fatal, panic)",
	)

	err := flag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		panic(err)
	}

	if len(clEndpoints) == 0 {
		fatalf("at least one consensus layer client endpoint is required")
	}

	beaconClients := make([]*beacon_client.BeaconClient, len(clEndpoints))

	for i, clEndpoint := range clEndpoints {
		// Configure an external CL
		externalCl, err := clients.ExternalClientFromURL(clEndpoint, "cl")
		if err != nil {
			fatalf(
				"error parsing consensus client url (%s): %v\n",
				clEndpoint,
				err,
			)
		}

		beaconCfg := beacon_client.BeaconClientConfig{}
		if clPort := externalCl.GetPort(); clPort != nil {
			beaconCfg.BeaconAPIPort = int(*clPort)
		}
		bn := &beacon_client.BeaconClient{
			Client: externalCl,
			Logger: &Logger{},
			Config: beaconCfg,
		}

		initctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second*time.Duration(clientInitTimeoutSeconds),
		)
		defer cancel()
		if err := bn.Init(initctx); err != nil {
			if initctx.Err() != nil {
				fatalf(
					"error initializing consensus client: %d second init timeout exceeded\n",
					clientInitTimeoutSeconds,
				)
			}
			fatalf(
				"error initializing consensus client: %v\n",
				err,
			)
		}
		beaconClients[i] = bn
	}

	blobberOpts := []config.Option{
		config.WithHost(hostIP),
		config.WithExternalIP(net.ParseIP(externalIP)),
		config.WithSpec(beaconClients[0].Config.Spec),
		config.WithBeaconGenesisTime(*beaconClients[0].Config.GenesisTime),
		config.WithGenesisValidatorsRoot(*beaconClients[0].Config.GenesisValidatorsRoot),
		config.WithValidatorKeysListFromFile(validatorKeyFilePath),
		config.WithProxiesPortStart(validatorProxyPortStart),
		config.WithSlotActionFrequency(uint64(slotActionFrequency)),
		config.WithMaxDevP2PSessionReuses(maxDevP2PSessionReuses),
		config.WithLogLevel(logLevel),
	}

	if slotActionJson != "" {
		slotAction, err := slot_actions.UnmarshallSlotAction([]byte(slotActionJson))
		if err != nil {
			fatalf("error parsing slot action: %v\n", err)
		}
		blobberOpts = append(blobberOpts, config.WithSlotAction(slotAction))
	}

	b, err := blobber.NewBlobber(context.Background(), blobberOpts...)
	if err != nil {
		fatalf("error creating blobber: %v\n", err)
	}

	for _, bn := range beaconClients {
		vp := b.AddBeaconClient(bn)
		logrus.WithFields(
			logrus.Fields{
				"ip":   externalIP,
				"port": vp.Port(),
			},
		).Info("Validator proxy started")
	}

	// Listen to SIGINT and SIGTERM signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	b.Close()
}
