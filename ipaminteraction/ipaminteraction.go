package ipaminteraction

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/henderiw/ipvlan-if/logging"
	"github.com/vishvananda/netlink"
)

type Net struct {
	Name       string      `json:"name"`
	CNIVersion string      `json:"cniVersion"`
	IPAM       *IPAMConfig `json:"ipam"`

	RuntimeConfig struct {
		IPs []string `json:"ips,omitempty"`
	} `json:"runtimeConfig,omitempty"`
	Args *struct {
		A *IPAMArgs `json:"cni"`
	} `json:"args"`
}

type IPAMConfig struct {
	Name      string
	Type      string         `json:"type"`
	Routes    []*types.Route `json:"routes"`
	Addresses []Address      `json:"addresses,omitempty"`
	DNS       types.DNS      `json:"dns"`
}

type IPAMEnvArgs struct {
	types.CommonArgs
	IP      types.UnmarshallableString `json:"ip,omitempty"`
	GATEWAY types.UnmarshallableString `json:"gateway,omitempty"`
}

type IPAMArgs struct {
	IPs []string `json:"ips"`
}

type Address struct {
	AddressStr string `json:"address"`
	Gateway    net.IP `json:"gateway,omitempty"`
	Address    net.IPNet
	Version    string
}

// canonicalizeIP makes sure a provided ip is in standard form
func canonicalizeIP(ip *net.IP) error {
	if ip.To4() != nil {
		*ip = ip.To4()
		return nil
	} else if ip.To16() != nil {
		*ip = ip.To16()
		return nil
	}
	return fmt.Errorf("IP %s not v4 nor v6", *ip)
}

// LoadIPAMConfig creates IPAMConfig using json encoded configuration provided
// as `bytes`. At the moment values provided in envArgs are ignored so there
// is no possibility to overload the json configuration using envArgs
func LoadIPAMConfig(ifAddr *netlink.Addr, bytes []byte, envArgs string) (*IPAMConfig, string, error) {
	n := Net{}
	if err := json.Unmarshal(bytes, &n); err != nil {
		return nil, "", err
	}

	//logging.Debugf("LoadIPAMConfig Net: %#v", n)
	//logging.Debugf("LoadIPAMConfig envArgs: %#v", envArgs)

	if n.IPAM == nil {
		logging.Debugf("IPAM config missing 'ipam' key")
		return nil, "", fmt.Errorf("IPAM config missing 'ipam' key")
	}

	if ifAddr != nil {
		logging.Debugf("IPAM ifAddr IP: %v", ifAddr.IP)
		logging.Debugf("IPAM ifAddr mask hex: %v", ifAddr.Mask)
		logging.Debugf("IPAM ifAddr mash dec: %v", net.IP(ifAddr.Mask))

		mask := net.IPMask(net.ParseIP(net.IP(ifAddr.Mask).String()).To4())
		prefixSize, _ := mask.Size()

		logging.Debugf("IPAM ifAddr mash dec: %v", prefixSize)

		n.IPAM.Addresses[0].AddressStr = ifAddr.IP.String() + "/" + strconv.Itoa(prefixSize)
		n.IPAM.Addresses[0].Address.IP = ifAddr.IP
		n.IPAM.Addresses[0].Address.Mask = ifAddr.Mask

		logging.Debugf("IPAM Addresses AddressStr: %v", n.IPAM.Addresses[0].AddressStr)
		logging.Debugf("IPAM Addresses Address: %v", n.IPAM.Addresses[0].Address)
		logging.Debugf("IPAM Addresses Address IP: %v", n.IPAM.Addresses[0].Address.IP)

		if err := canonicalizeIP(&n.IPAM.Addresses[0].Address.IP); err != nil {
			return nil, "", logging.Debugf("invalid address %d: %s", 0, err)
		}

		if n.IPAM.Addresses[0].Address.IP.To4() != nil {
			n.IPAM.Addresses[0].Version = "4"
		} else {
			n.IPAM.Addresses[0].Version = "6"
		}

		logging.Debugf("IPAM Addresses Address Version: %v", n.IPAM.Addresses[0].Version)
	}

	// Copy net name into IPAM so not to drag Net struct around
	n.IPAM.Name = n.Name
	logging.Debugf("IPAM name: %v", n.IPAM.Name)

	return n.IPAM, n.CNIVersion, nil
}
