package blobber

import (
	"fmt"
	"net"
	"sync"

	"github.com/marioevz/eth-clients/clients/validator"
	beacon "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/tree"
)

type config struct {
	id                    int
	port                  int
	proxiesPortStart      int
	host                  string
	spec                  *beacon.Spec
	externalIP            net.IP
	beaconGenesisTime     beacon.Timestamp
	genesisValidatorsRoot tree.Root
	validatorKeys         map[beacon.ValidatorIndex]*validator.ValidatorKeys

	mutex sync.Mutex
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
			b.cfg.mutex.Lock()
			defer b.cfg.mutex.Unlock()
			b.cfg.id = id
			return nil
		},
		description: fmt.Sprintf("WithID(%d)", id),
	}
}

func WithHost(host string) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.mutex.Lock()
			defer b.cfg.mutex.Unlock()
			b.cfg.host = host
			return nil
		},
		description: fmt.Sprintf("WithHost(%s)", host),
	}
}

func WithExternalIP(ip net.IP) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.mutex.Lock()
			defer b.cfg.mutex.Unlock()
			b.cfg.externalIP = ip
			return nil
		},
		description: fmt.Sprintf("WithExternalIP(%s)", ip),
	}
}

func WithPort(port int) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.mutex.Lock()
			defer b.cfg.mutex.Unlock()
			b.cfg.port = port
			return nil
		},
		description: fmt.Sprintf("WithPort(%d)", port),
	}
}

func WithProxiesPortStart(portStart int) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.mutex.Lock()
			defer b.cfg.mutex.Unlock()
			b.cfg.proxiesPortStart = portStart
			return nil
		},
		description: fmt.Sprintf("WithProxiesPortStart(%d)", portStart),
	}
}

func WithSpec(spec *beacon.Spec) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.mutex.Lock()
			defer b.cfg.mutex.Unlock()
			b.cfg.spec = spec
			return nil
		},
		description: "WithSpec", // TODO: actually format the spec
	}
}

func WithBeaconGenesisTime(t beacon.Timestamp) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.mutex.Lock()
			defer b.cfg.mutex.Unlock()
			b.cfg.beaconGenesisTime = t
			return nil
		},
		description: fmt.Sprintf("WithBeaconGenesisTime(%d)", t),
	}
}

func WithGenesisValidatorsRoot(t tree.Root) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.mutex.Lock()
			defer b.cfg.mutex.Unlock()
			b.cfg.genesisValidatorsRoot = t
			return nil
		},
		description: fmt.Sprintf("WithGenesisValidatorsRoot(0x%x)", t),
	}
}

func WithValidatorKeys(vk map[beacon.ValidatorIndex]*validator.ValidatorKeys) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.mutex.Lock()
			defer b.cfg.mutex.Unlock()
			b.cfg.validatorKeys = vk
			return nil
		},
		description: fmt.Sprintf("WithValidatorKeys(%d)", len(vk)),
	}
}

func WithValidatorKeysArray(vk []*validator.ValidatorKeys) Option {
	return Option{
		apply: func(b *Blobber) error {
			b.cfg.mutex.Lock()
			defer b.cfg.mutex.Unlock()
			vkMap := make(map[beacon.ValidatorIndex]*validator.ValidatorKeys)
			for i, v := range vk {
				vkMap[beacon.ValidatorIndex(i)] = v
			}
			b.cfg.validatorKeys = vkMap
			return nil
		},
		description: fmt.Sprintf("WithValidatorKeys(%d)", len(vk)),
	}
}
