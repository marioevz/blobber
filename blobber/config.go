package blobber

import (
	"fmt"
	"net"
	"sync"

	beacon "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/tree"
	"github.com/sirupsen/logrus"
)

type config struct {
	sync.Mutex

	id                     int
	port                   int
	proxiesPortStart       int
	host                   string
	spec                   *beacon.Spec
	externalIP             net.IP
	beaconGenesisTime      beacon.Timestamp
	genesisValidatorsRoot  tree.Root
	validatorKeys          map[beacon.ValidatorIndex]*ValidatorKey
	validatorKeysList      []*ValidatorKey
	maxDevP2PSessionReuses int

	slotAction          SlotAction
	slotActionFrequency uint64
}

type Option struct {
	apply       func(b *Blobber) error
	description string
}

func (o Option) MarshalText() ([]byte, error) {
	return []byte(o.description), nil
}

func WithID(id int) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.Lock()
			defer b.cfg.Unlock()
			b.cfg.id = id
			return nil
		},
		description: fmt.Sprintf("WithID(%d)", id),
	}
}

func WithHost(host string) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.Lock()
			defer b.cfg.Unlock()
			b.cfg.host = host
			return nil
		},
		description: fmt.Sprintf("WithHost(%s)", host),
	}
}

func WithExternalIP(ip net.IP) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.Lock()
			defer b.cfg.Unlock()
			b.cfg.externalIP = ip
			return nil
		},
		description: fmt.Sprintf("WithExternalIP(%s)", ip),
	}
}

func WithPort(port int) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.Lock()
			defer b.cfg.Unlock()
			b.cfg.port = port
			return nil
		},
		description: fmt.Sprintf("WithPort(%d)", port),
	}
}

func WithLogLevel(level string) Option {
	return Option{
		apply: func(_ *Blobber) error {
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

func WithMaxDevP2PSessionReuses(reuse int) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.Lock()
			defer b.cfg.Unlock()
			b.cfg.maxDevP2PSessionReuses = reuse
			return nil
		},
		description: fmt.Sprintf("WithMaxDevP2PSessionReuses(%d)", reuse),
	}
}

func WithProxiesPortStart(portStart int) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.Lock()
			defer b.cfg.Unlock()
			b.cfg.proxiesPortStart = portStart
			return nil
		},
		description: fmt.Sprintf("WithProxiesPortStart(%d)", portStart),
	}
}

func WithSpec(spec *beacon.Spec) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.Lock()
			defer b.cfg.Unlock()
			b.cfg.spec = spec
			return nil
		},
		description: "WithSpec", // TODO: actually format the spec
	}
}

func WithBeaconGenesisTime(t beacon.Timestamp) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.Lock()
			defer b.cfg.Unlock()
			b.cfg.beaconGenesisTime = t
			return nil
		},
		description: fmt.Sprintf("WithBeaconGenesisTime(%d)", t),
	}
}

func WithGenesisValidatorsRoot(t tree.Root) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.Lock()
			defer b.cfg.Unlock()
			b.cfg.genesisValidatorsRoot = t
			return nil
		},
		description: fmt.Sprintf("WithGenesisValidatorsRoot(0x%x)", t),
	}
}

func WithValidatorKeys(vk map[beacon.ValidatorIndex]*ValidatorKey) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.Lock()
			defer b.cfg.Unlock()
			b.cfg.validatorKeys = vk
			return nil
		},
		description: fmt.Sprintf("WithValidatorKeys(%d)", len(vk)),
	}
}

func WithValidatorKeysList(vk []*ValidatorKey) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.Lock()
			defer b.cfg.Unlock()
			b.cfg.validatorKeysList = vk
			return nil
		},
		description: fmt.Sprintf("WithValidatorKeys(%d)", len(vk)),
	}
}

func WithValidatorKeysListFromFile(path string) Option {
	return Option{
		apply: func(b *Blobber) error {
			vk, err := KeyListFromFile(path)
			if err != nil {
				return err
			}
			b.cfg.Lock()
			defer b.cfg.Unlock()
			b.cfg.validatorKeysList = vk
			return nil
		},
		description: fmt.Sprintf("WithValidatorKeysListFromFile(%s)", path),
	}
}

func WithSlotAction(action SlotAction) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.Lock()
			defer b.cfg.Unlock()
			b.cfg.slotAction = action
			return nil
		},
		description: fmt.Sprintf("WithSlotAction(%s)", action),
	}
}

func WithSlotActionFrequency(freq uint64) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.Lock()
			defer b.cfg.Unlock()
			b.cfg.slotActionFrequency = freq
			return nil
		},
		description: fmt.Sprintf("WithSlotActionFrequency(%d)", freq),
	}
}
