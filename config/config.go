package config

import (
	"fmt"
	"net"
	"sync"

	"github.com/marioevz/blobber/keys"
	"github.com/marioevz/blobber/p2p"
	"github.com/marioevz/blobber/proposal_actions"
	beacon "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/tree"
	"github.com/sirupsen/logrus"
)

type Config struct {
	sync.Mutex

	*p2p.TestP2P

	ID                           uint64
	Port                         int
	ApiPort                      int
	ProxiesPortStart             int
	Host                         string
	Spec                         *beacon.Spec
	ExternalIP                   net.IP
	BeaconGenesisTime            beacon.Timestamp
	GenesisValidatorsRoot        tree.Root
	ValidatorKeys                map[beacon.ValidatorIndex]*keys.ValidatorKey
	ValidatorKeysList            []*keys.ValidatorKey
	AlwaysErrorValidatorResponse bool

	ValidatorLoadTimeoutSeconds int

	ProposalAction proposal_actions.ProposalAction
}

func (cfg *Config) Apply(opts ...Option) error {
	for _, opt := range opts {
		if err := opt.apply(cfg); err != nil {
			return err
		}
	}
	return nil
}

type Option struct {
	apply       func(cfg *Config) error
	description string
}

func (o Option) MarshalText() ([]byte, error) {
	return []byte(o.description), nil
}

func WithID(id uint64) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.ID = id
			cfg.TestP2P.InstanceID = id
			return nil
		},
		description: fmt.Sprintf("WithID(%d)", id),
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
		description: fmt.Sprintf("WithHost(%s)", host),
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
		description: fmt.Sprintf("WithExternalIP(%s)", ip),
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
		description: fmt.Sprintf("WithPort(%d)", port),
	}
}

func WithBeaconPortStart(port int) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.TestP2P.BeaconPortStart = int64(port)
			return nil
		},
		description: fmt.Sprintf("WithBeaconPortStart(%d)", port),
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
		description: fmt.Sprintf("WithLogLevel(%s)", level),
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
		description: fmt.Sprintf("WithValidatorLoadTimeoutSeconds(%d)", timeout),
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
		description: fmt.Sprintf("WithMaxDevP2PSessionReuses(%d)", reuse),
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
		description: fmt.Sprintf("WithProxiesPortStart(%d)", portStart),
	}
}

func WithSpec(spec *beacon.Spec) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.Spec = spec
			return nil
		},
		description: "WithSpec", // TODO: actually format the spec
	}
}

func WithBeaconGenesisTime(t beacon.Timestamp) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.BeaconGenesisTime = t
			return nil
		},
		description: fmt.Sprintf("WithBeaconGenesisTime(%d)", t),
	}
}

func WithGenesisValidatorsRoot(t tree.Root) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.GenesisValidatorsRoot = t
			return nil
		},
		description: fmt.Sprintf("WithGenesisValidatorsRoot(0x%x)", t),
	}
}

func WithValidatorKeys(vk map[beacon.ValidatorIndex]*keys.ValidatorKey) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.ValidatorKeys = vk
			return nil
		},
		description: fmt.Sprintf("WithValidatorKeys(%d)", len(vk)),
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
		description: fmt.Sprintf("WithValidatorKeys(%d)", len(vk)),
	}
}

func WithValidatorKeysListFromFile(path string) Option {
	return Option{
		apply: func(cfg *Config) error {
			vk, err := keys.KeyListFromFile(path)
			if err != nil {
				return err
			}
			cfg.Lock()
			defer cfg.Unlock()
			cfg.ValidatorKeysList = vk
			return nil
		},
		description: fmt.Sprintf("WithValidatorKeysListFromFile(%s)", path),
	}
}

func WithValidatorKeysListFromFolder(path string) Option {
	return Option{
		apply: func(cfg *Config) error {
			vk, err := keys.KeyListFromFolder(path)
			if err != nil {
				return err
			}
			cfg.Lock()
			defer cfg.Unlock()
			cfg.ValidatorKeysList = vk
			return nil
		},
		description: fmt.Sprintf("WithValidatorKeysListFromFolder(%s)", path),
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
		description: fmt.Sprintf("WithProposalAction(%s)", action),
	}
}

func WithProposalActionFrequency(freq uint64) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			if cfg.ProposalAction == nil {
				return fmt.Errorf("cannot set ProposalActionFrequency without ProposalAction")
			}
			cfg.ProposalAction.SetFrequency(freq)
			return nil
		},
		description: fmt.Sprintf("WithProposalActionFrequency(%d)", freq),
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
		description: "WithAlwaysErrorValidatorResponse()",
	}
}

func WithApiPort(port int) Option {
	return Option{
		apply: func(cfg *Config) error {
			cfg.Lock()
			defer cfg.Unlock()
			cfg.ApiPort = port
			return nil
		},
		description: fmt.Sprintf("WithApiPort(%d)", port),
	}
}
