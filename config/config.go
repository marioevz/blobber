package config

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/marioevz/blobber/keys"
	"github.com/marioevz/blobber/p2p"
	"github.com/marioevz/blobber/proposal_actions"
	"github.com/sirupsen/logrus"
)

type Config struct {
	sync.Mutex

	*p2p.TestP2P

	ID                           uint64
	Port                         int
	ProxiesPortStart             int
	Host                         string
	Spec                         map[string]interface{} // Spec configuration as used by go-eth2-client
	ExternalIP                   net.IP
	BeaconGenesisTime            uint64
	GenesisValidatorsRoot        phase0.Root
	ValidatorKeys                map[phase0.ValidatorIndex]*keys.ValidatorKey
	ValidatorKeysList            []*keys.ValidatorKey
	AlwaysErrorValidatorResponse bool

	ValidatorLoadTimeoutSeconds int

	ProposalAction proposal_actions.ProposalAction

	// P2P configuration
	StaticPeers []string
	Bootnodes   []string
}

func (cfg *Config) Apply(opts ...Option) error {
	logrus.Infof("Config.Apply called with %d options", len(opts))
	for i, opt := range opts {
		logrus.Infof("Applying option %d: %s", i, opt.Description)
		if err := opt.apply(cfg); err != nil {
			logrus.Errorf("Failed to apply option %d (%s): %v", i, opt.Description, err)
			return err
		}
		logrus.Infof("Successfully applied option %d: %s", i, opt.Description)
	}
	logrus.Info("All options applied successfully")
	return nil
}

type Option struct {
	apply       func(cfg *Config) error
	Description string
}

func (o Option) MarshalText() ([]byte, error) {
	return []byte(o.Description), nil
}

func WithID(id uint64) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.ID = id
			cfg.InstanceID = id
			return nil
		},
		Description: fmt.Sprintf("WithID(%d)", id),
	}
}

func WithHost(host string) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.Host = host
			return nil
		},
		Description: fmt.Sprintf("WithHost(%s)", host),
	}
}

func WithExternalIP(ip net.IP) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.ExternalIP = ip
			cfg.TestP2P.ExternalIP = ip
			return nil
		},
		Description: fmt.Sprintf("WithExternalIP(%s)", ip),
	}
}

func WithPort(port int) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.Port = port
			return nil
		},
		Description: fmt.Sprintf("WithPort(%d)", port),
	}
}

func WithBeaconPortStart(port int) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.BeaconPortStart = int64(port)
			return nil
		},
		Description: fmt.Sprintf("WithBeaconPortStart(%d)", port),
	}
}

func WithLogLevel(level string) Option {
	return Option{
		apply: func(_ *Config) error {
			lvl, err := logrus.ParseLevel(level)
			if err != nil {
				return err
			}
			logrus.SetLevel(lvl)
			return nil
		},
		Description: fmt.Sprintf("WithLogLevel(%s)", level),
	}
}

func WithValidatorLoadTimeoutSeconds(timeout int) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.ValidatorLoadTimeoutSeconds = timeout
			return nil
		},
		Description: fmt.Sprintf("WithValidatorLoadTimeoutSeconds(%d)", timeout),
	}
}

func WithMaxDevP2PSessionReuses(reuse int) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.MaxDevP2PSessionReuses = reuse
			return nil
		},
		Description: fmt.Sprintf("WithMaxDevP2PSessionReuses(%d)", reuse),
	}
}

func WithProxiesPortStart(portStart int) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.ProxiesPortStart = portStart
			return nil
		},
		Description: fmt.Sprintf("WithProxiesPortStart(%d)", portStart),
	}
}

func WithSpec(spec map[string]interface{}) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.Spec = spec
			return nil
		},
		Description: fmt.Sprintf("WithSpec(%d keys)", len(spec)),
	}
}

func WithBeaconGenesisTime(t uint64) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.BeaconGenesisTime = t
			return nil
		},
		Description: fmt.Sprintf("WithBeaconGenesisTime(%d)", t),
	}
}

func WithGenesisValidatorsRoot(t phase0.Root) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.GenesisValidatorsRoot = t
			return nil
		},
		Description: fmt.Sprintf("WithGenesisValidatorsRoot(0x%x)", t),
	}
}

func WithValidatorKeys(vk map[phase0.ValidatorIndex]*keys.ValidatorKey) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.ValidatorKeys = vk
			return nil
		},
		Description: fmt.Sprintf("WithValidatorKeys(%d)", len(vk)),
	}
}

func WithValidatorKeysList(vk []*keys.ValidatorKey) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.ValidatorKeysList = vk
			return nil
		},
		Description: fmt.Sprintf("WithValidatorKeys(%d)", len(vk)),
	}
}

func WithValidatorKeysListFromFile(ctx context.Context, path string) Option {
	return Option{
		apply: func(cfg *Config) error {
			vk, err := keys.KeyListFromFile(ctx, path)
			if err != nil {
				return err
			}
			cfg.Lock()
			defer cfg.Unlock()
			cfg.ValidatorKeysList = vk
			return nil
		},
		Description: fmt.Sprintf("WithValidatorKeysListFromFile(%s)", path),
	}
}

func WithValidatorKeysListFromFolder(ctx context.Context, path string) Option {
	return Option{
		apply: func(cfg *Config) error {
			vk, err := keys.KeyListFromFolder(ctx, path)
			if err != nil {
				return err
			}
			cfg.Lock()
			defer cfg.Unlock()
			cfg.ValidatorKeysList = vk
			return nil
		},
		Description: fmt.Sprintf("WithValidatorKeysListFromFolder(%s)", path),
	}
}

func WithProposalAction(action proposal_actions.ProposalAction) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.ProposalAction = action
			return nil
		},
		Description: fmt.Sprintf("WithProposalAction(%s)", action),
	}
}

func WithProposalActionFrequency(freq uint64) Option {
	// This function should not be called anymore!
	fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	fmt.Printf("!!! UNEXPECTED CALL TO WithProposalActionFrequency !!!\n")
	fmt.Printf("!!! freq=%d !!!\n", freq)
	fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	fmt.Println("Stack trace:")
	for i := 1; i < 10; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		fmt.Printf("  %s:%d %s\n", file, line, runtime.FuncForPC(pc).Name())
	}
	fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			if cfg.ProposalAction == nil {
				// Store the frequency for later use when proposal action is set
				// This handles the case where options might be applied in different order
				logrus.Warnf("ProposalAction not yet set, cannot set frequency %d", freq)
				return fmt.Errorf("cannot set ProposalActionFrequency without ProposalAction")
			}
			cfg.ProposalAction.SetFrequency(freq)
			return nil
		},
		Description: fmt.Sprintf("WithProposalActionFrequency(%d)", freq),
	}
}

func WithAlwaysErrorValidatorResponse() Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.AlwaysErrorValidatorResponse = true
			return nil
		},
		Description: "WithAlwaysErrorValidatorResponse()",
	}
}

func WithStaticPeers(peers []string) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.StaticPeers = peers
			return nil
		},
		Description: fmt.Sprintf("WithStaticPeers(%d peers)", len(peers)),
	}
}

func WithBootnodes(bootnodes []string) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.Bootnodes = bootnodes
			return nil
		},
		Description: fmt.Sprintf("WithBootnodes(%d nodes)", len(bootnodes)),
	}
}
