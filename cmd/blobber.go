package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/marioevz/blobber"
	"github.com/marioevz/blobber/beacon"
	"github.com/marioevz/blobber/config"
	"github.com/marioevz/blobber/proposal_actions"
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
		clEndpoints                       arrayFlags
		nonValidatingClEndpoints          arrayFlags
		externalIP                        string
		hostIP                            string
		clientInitTimeoutSeconds          int
		stateValidatorFetchTimeoutSeconds int
		logLevel                          string
		validatorKeyFilePath              string
		validatorKeyFolderPath            string
		proposalActionJson                string
		proposalActionFrequency           int
		beaconPortStart                   int
		validatorProxyPortStart           int
		maxDevP2PSessionReuses            int
		blobberID                         uint64
		unsafeMode                        bool
	)

	flag.Var(
		&clEndpoints,
		"cl",
		"Consensus layer client endpoint that creates a validator proxy endpoint",
	)
	flag.Var(
		&nonValidatingClEndpoints,
		"cl-non-validating",
		"Consensus layer client endpoint to add as a non-validating client: all messages are broadcast to it, but it's not expected to have valiadtor duties",
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
	flag.StringVar(
		&validatorKeyFolderPath,
		"validator-key-folder",
		"",
		"Path to validator key folder: Load keys from a folder that contains a 'secrets' and 'keys' subdirectories",
	)
	flag.IntVar(
		&clientInitTimeoutSeconds,
		"client-init-timeout",
		60,
		"clients initialization wait timeout in seconds",
	)
	flag.IntVar(
		&stateValidatorFetchTimeoutSeconds,
		"state-validator-load-timeout",
		0,
		"state validators request timeout in seconds",
	)
	flag.IntVar(
		&beaconPortStart,
		"beacon-port-start",
		9_000,
		"Port number to start the beacon gossip p2p listen port from. For each beacon node added, there will be one extra port used",
	)
	flag.IntVar(
		&validatorProxyPortStart,
		"validator-proxy-port-start",
		20_000,
		"Port number to start validator proxy listening ports from. For each beacon node added, there will be one extra port used.",
	)
	flag.StringVar(
		&proposalActionJson,
		"proposal-action",
		"",
		"Description of the proposal action to execute in JSON formatted string. See proposal_actions.go for examples.",
	)
	flag.IntVar(
		&proposalActionFrequency,
		"proposal-action-frequency",
		1,
		"Frequency of proposal actions in proposals. 1 means execute every proposal, 2 means execute every other proposal, etc.",
	)
	flag.IntVar(
		&maxDevP2PSessionReuses,
		"max-dev-p2p-session-reuses",
		0,
		"Maximum number of times to reuse a DevP2P session, which results in a new PeerID. 0 means always use the same session.",
	)
	flag.Uint64Var(
		&blobberID,
		"id",
		0,
		"Sets the blobber ID for this instance, it affects the PeerIDs that will be generated during runtime.",
	)
	flag.StringVar(
		&logLevel,
		"log-level",
		"info",
		"Sets the log level (trace, debug, info, warn, error, fatal, panic)",
	)
	flag.BoolVar(
		&unsafeMode,
		"enable-unsafe-mode",
		false,
		"Enable unsafe mode, only use this if you know what you're doing and never attempt to run this tool on mainnet.",
	)

	err := flag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		panic(err)
	}

	if !unsafeMode {
		fmt.Printf("WARNING: Some of the actions performed by this tool are unsafe and will get a validator SLASHED. Never run this tool on mainnet, and only run in test networks. If you know what you're doing, use the --enable-unsafe-mode flag to ignore this warning an proceed.\n\n")
		os.Exit(1)
	}

	if len(clEndpoints) == 0 {
		fatalf("at least one consensus layer client endpoint is required")
	}

	type beaconEndpoint struct {
		BeaconClient *beacon.BeaconClientAdapter
		Validator    bool
	}

	beaconClients := make([]beaconEndpoint, len(clEndpoints)+len(nonValidatingClEndpoints))

	var wg sync.WaitGroup

	addBeaconClient := func(i int, clEndpoint string, validator bool) {
		defer wg.Done()
		// Parse the beacon client URL
		beaconAPIURL, err := beacon.ParseBeaconURL(clEndpoint)
		if err != nil {
			fatalf(
				"error parsing consensus client url (%s): %v\n",
				clEndpoint,
				err,
			)
		}
		
		initctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second*time.Duration(clientInitTimeoutSeconds),
		)
		defer cancel()
		
		// Create our new beacon client adapter
		adapter, err := beacon.NewBeaconClientAdapter(initctx, beaconAPIURL)
		if err != nil {
			fatalf("error creating beacon client adapter: %v\n", err)
		}
		
		// Set up logger on the adapter's embedded BeaconClient
		if adapter.BeaconClient != nil {
			adapter.BeaconClient.Logger = &Logger{}
			
			// Initialize the old client (this populates spec and other fields)
			if err := adapter.BeaconClient.Init(initctx); err != nil {
				// Log warning but continue as we're using the new client
				logrus.WithError(err).Warn("Failed to initialize old beacon client")
			}
		}
		
		beaconClients[i] = beaconEndpoint{
			BeaconClient: adapter,
			Validator:    validator,
		}
	}

	for i, clEndpoint := range clEndpoints {
		wg.Add(1)
		go addBeaconClient(i, clEndpoint, true)
	}
	for i, clEndpoint := range nonValidatingClEndpoints {
		wg.Add(1)
		go addBeaconClient(i+len(clEndpoints), clEndpoint, false)
	}
	wg.Wait()

	// Build base options first
	blobberOpts := []config.Option{
		config.WithHost(hostIP),
		config.WithExternalIP(net.ParseIP(externalIP)),
		config.WithID(blobberID),
		config.WithSpec(beaconClients[0].BeaconClient.Config.Spec),
		config.WithBeaconGenesisTime(uint64(beaconClients[0].BeaconClient.Config.GenesisTime.Unix())),
		config.WithGenesisValidatorsRoot(*beaconClients[0].BeaconClient.Config.GenesisValidatorsRoot),
		config.WithBeaconPortStart(beaconPortStart),
		config.WithProxiesPortStart(validatorProxyPortStart),
		config.WithMaxDevP2PSessionReuses(maxDevP2PSessionReuses),
		config.WithLogLevel(logLevel),
	}

	if validatorKeyFilePath != "" && validatorKeyFolderPath != "" {
		fatalf("cannot specify both validator-key-file and validator-key-folder")
	}

	if validatorKeyFilePath != "" {
		blobberOpts = append(blobberOpts, config.WithValidatorKeysListFromFile(validatorKeyFilePath))
	} else if validatorKeyFolderPath != "" {
		blobberOpts = append(blobberOpts, config.WithValidatorKeysListFromFolder(validatorKeyFolderPath))
	}

	// Debug output - print all args
	logrus.Infof("All args: %v", os.Args)
	logrus.Infof("proposalActionJson: '%s' (len=%d)", proposalActionJson, len(proposalActionJson))
	logrus.Infof("proposalActionFrequency: %d", proposalActionFrequency)
	
	// Handle proposal action and frequency together
	// Trim any whitespace that might have been introduced
	proposalActionJson = strings.TrimSpace(proposalActionJson)
	
	if proposalActionJson != "" && proposalActionJson != "{}" {
		logrus.Infof("Parsing proposal action JSON...")
		proposalAction, err := proposal_actions.UnmarshallProposalAction([]byte(proposalActionJson))
		if err != nil {
			fatalf("error parsing proposal action JSON '%s': %v\n", proposalActionJson, err)
		}
		logrus.Infof("Successfully parsed proposal action: %v", proposalAction)
		
		// Set the frequency on the proposal action before adding it
		if proposalActionFrequency > 0 {
			logrus.Infof("Setting frequency %d on proposal action before adding to options", proposalActionFrequency)
			proposalAction.SetFrequency(uint64(proposalActionFrequency))
		}
		
		// Now add the proposal action with frequency already set
		blobberOpts = append(blobberOpts, config.WithProposalAction(proposalAction))
	} else if proposalActionFrequency != 1 {
		// If no proposal action but frequency is set to non-default value, error out
		fatalf("proposal-action-frequency=%d specified but no proposal-action provided\n", proposalActionFrequency)
	}

	if stateValidatorFetchTimeoutSeconds > 0 {
		blobberOpts = append(blobberOpts, config.WithValidatorLoadTimeoutSeconds(stateValidatorFetchTimeoutSeconds))
	}

	b, err := blobber.NewBlobber(context.Background(), blobberOpts...)
	if err != nil {
		fatalf("error creating blobber: %v\n", err)
	}

	for _, bn := range beaconClients {
		// Pass the adapter itself
		vp := b.AddBeaconClient(bn.BeaconClient, bn.Validator)
		if vp != nil {
			logrus.WithFields(
				logrus.Fields{
					"ip":   externalIP,
					"port": vp.Port(),
				},
			).Info("Validator proxy started")
		}
	}

	// Listen to SIGINT and SIGTERM signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	b.Close()
}
