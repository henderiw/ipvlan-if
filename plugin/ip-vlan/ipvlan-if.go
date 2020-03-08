package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"

	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/henderiw/ipvlan-if/ipaminteraction"
	"github.com/henderiw/ipvlan-if/logging"
	"github.com/vishvananda/netlink/nl"
)

// Family type definitions
const (
	FAMILY_ALL  = nl.FAMILY_ALL
	FAMILY_V4   = nl.FAMILY_V4
	FAMILY_V6   = nl.FAMILY_V6
	FAMILY_MPLS = nl.FAMILY_MPLS
)

type NetConf struct {
	types.NetConf
	LogFile  string `json:"logFile"`
	LogLevel string `json:"logLevel"`
	Master   string `json:"master"`
	Mode     string `json:"mode"`
	MTU      int    `json:"mtu"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func loadConf(bytes []byte, cmdCheck bool) (*NetConf, string, error) {
	n := &NetConf{}

	logging.Debugf("loadConf: %s", string(bytes))
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", logging.Errorf("failed to load netconf: %v", err)
	}

	// Logging
	if n.LogFile != "" {
		logging.SetLogFile(n.LogFile)
	}
	if n.LogLevel != "" {
		logging.SetLogLevel(n.LogLevel)
	}

	if cmdCheck {
		return n, n.CNIVersion, nil
	}

	var result *current.Result
	var err error
	// Parse previous result
	if n.NetConf.RawPrevResult != nil {
		if err = version.ParsePrevResult(&n.NetConf); err != nil {
			return nil, "", logging.Errorf("could not parse prevResult: %v", err)
		}

		result, err = current.NewResultFromResult(n.PrevResult)
		if err != nil {
			return nil, "", logging.Errorf("could not convert result to current version: %v", err)
		}
	}
	//n.Master = "eth0"
	if n.Master == "" {
		if result == nil {
			return nil, "", logging.Errorf(`"master" field is required. It specifies the host interface name to virtualize`)
		}
		if len(result.Interfaces) == 1 && result.Interfaces[0].Name != "" {
			n.Master = result.Interfaces[0].Name
		} else {
			return nil, "", logging.Errorf("chained master failure. PrevResult lacks a single named interface")
		}
	}
	return n, n.CNIVersion, nil
}

func modeFromString(s string) (netlink.IPVlanMode, error) {
	switch s {
	case "", "l2":
		return netlink.IPVLAN_MODE_L2, nil
	case "l3":
		return netlink.IPVLAN_MODE_L3, nil
	case "l3s":
		return netlink.IPVLAN_MODE_L3S, nil
	default:
		return 0, logging.Errorf("unknown ipvlan mode: %q", s)
	}
}

func modeToString(mode netlink.IPVlanMode) (string, error) {
	switch mode {
	case netlink.IPVLAN_MODE_L2:
		return "l2", nil
	case netlink.IPVLAN_MODE_L3:
		return "l3", nil
	case netlink.IPVLAN_MODE_L3S:
		return "l3s", nil
	default:
		return "", logging.Errorf("unknown ipvlan mode: %q", mode)
	}
}

func createIpvlan(conf *NetConf, ifName string, netns ns.NetNS) (*current.Interface, *netlink.Addr, error) {
	ipvlan := &current.Interface{}

	//ifName = "eth0"

	mode, err := modeFromString(conf.Mode)
	if err != nil {
		return nil, nil, err
	}

	logging.Debugf("createIpvlan ifName: ", ifName)
	logging.Debugf("createIpvlan mode: ", mode)

	m, err := netlink.LinkByName(conf.Master)
	if err != nil {
		return nil, nil, logging.Errorf("failed to lookup master %q: %v", conf.Master, err)
	}

	addrs, err := netlink.AddrList(m, FAMILY_ALL)
	found := false
	index := 0
	for i := 0; i < len(addrs); i++ {
		family := nl.GetIPFamily(addrs[i].IP)
		logging.Debugf("\n")
		logging.Debugf("addrs family: %v", family)
		logging.Debugf("addrs IPNet IP: %v", addrs[i].IP)
		logging.Debugf("addrs IPNet Mask: %v", addrs[i].Mask)
		logging.Debugf("addrs label: %v", addrs[i].Label)
		logging.Debugf("addrs flags: %d", addrs[i].Flags)
		logging.Debugf("addrs Scope: %d", addrs[i].Scope)
		//logging.Debugf("addrs Peer IP: %#v", addrs[i].Peer.IP)
		//logging.Debugf("addrs Peer MAsk: %#v", addrs[i].Peer.Mask)
		logging.Debugf("addrs Broadcast: %v", addrs[i].Broadcast)
		logging.Debugf("addrs PreferedLft: %v", addrs[i].PreferedLft)
		logging.Debugf("addrs ValidLft: %v", addrs[i].ValidLft)

		if family == 2 {
			found = true
			index = i
		}
	}

	if found == true {
		logging.Debugf("\n")
		logging.Debugf("DELETE INTERFACE ADDRESS: %v", addrs[index].IP)
		logging.Debugf("DELETE INTERFACE ADDRESS: %v", addrs[index].Mask)
		logging.Debugf("\n")

		err := netlink.AddrDel(m, &addrs[index])
		if err != nil {
			logging.Errorf("Error deleting interface")
		}
	}

	// due to kernel bug we have to create with tmpname or it might
	// collide with the name on the host and error out
	tmpName, err := ip.RandomVethName()
	if err != nil {
		return nil, nil, err
	}

	mv := &netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			MTU:         conf.MTU,
			Name:        tmpName,
			ParentIndex: m.Attrs().Index,
			Namespace:   netlink.NsFd(int(netns.Fd())),
		},
		Mode: mode,
	}

	if err := netlink.LinkAdd(mv); err != nil {
		return nil, nil, logging.Errorf("failed to create ipvlan: %v", err)
	}

	err = netns.Do(func(_ ns.NetNS) error {
		err := ip.RenameLink(tmpName, ifName)
		if err != nil {
			return logging.Errorf("failed to rename ipvlan to %q: %v", ifName, err)
		}
		ipvlan.Name = ifName

		// Re-fetch ipvlan to get all properties/attributes
		contIpvlan, err := netlink.LinkByName(ipvlan.Name)
		if err != nil {
			return logging.Errorf("failed to refetch ipvlan %q: %v", ipvlan.Name, err)
		}
		ipvlan.Mac = contIpvlan.Attrs().HardwareAddr.String()
		//ipvlan.IP = contIpvlan.Attrs().OperState
		ipvlan.Sandbox = netns.Path()

		logging.Debugf("createIpvlan: %v, %#v", ipvlan.Mac, ipvlan.Sandbox)

		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	if found == true {
		return ipvlan, &addrs[index], nil
	}
	return ipvlan, nil, nil

}

func cmdAdd(args *skel.CmdArgs) error {

	//args.IfName = "eth0"

	n, cniVersion, err := loadConf(args.StdinData, false)
	if err != nil {
		return err
	}

	logging.Debugf("cmdAdd args.Args: %#v", args.Args)

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return logging.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	//logging.Debugf("cmdAdd: %#v, %v, %v, %v, %#v ", n, args.Netns, n.IPAM.Type, args.IfName, n.PrevResult)
	//logging.Debugf("cmdAdd n.IPAM.Type: %v", n.IPAM.Type)
	//logging.Debugf("cmdAdd n.IPAM.Subnet: %v", n.IPAM.Subnet)
	//logging.Debugf("cmdAdd n.IPAM.RangeStart: %v", n.IPAM.RangeStart)
	//logging.Debugf("cmdAdd n.IPAM.RangeEnd: %v", n.IPAM.RangeEnd)

	ipvlanInterface, ifAddr, err := createIpvlan(n, args.IfName, netns)
	if err != nil {
		return err
	}

	logging.Debugf("cmdAdd ifAddr: %v", ifAddr.IP)
	logging.Debugf("cmdAdd ifAddr: %v", ifAddr.Mask)

	if n.IPAM.Type != "static" {
		logging.Debugf("only IPAM type static supported with this CNI")
		err = fmt.Errorf("only IPAM type static supported with this CNI")
		return err
	}

	//var result *current.Result

	ipamConf, confVersion, err := ipaminteraction.LoadIPAMConfig(ifAddr, args.StdinData, args.Args)
	if err != nil {
		return err
	}
	logging.Debugf("ipaminteraction.LoadIPAMConfig ipamConf, %#v", ipamConf)
	logging.Debugf("ipaminteraction.LoadIPAMConfig confVersion, %#v", confVersion)
	result := &current.Result{}
	result.CNIVersion = confVersion
	result.DNS = ipamConf.DNS
	result.Routes = ipamConf.Routes
	for _, v := range ipamConf.Addresses {
		result.IPs = append(result.IPs, &current.IPConfig{
			Version: v.Version,
			Address: v.Address,
			Gateway: v.Gateway})
	}

	logging.Debugf("IPAM Add result CNIVersion: %#v", result.CNIVersion)
	for _, int := range result.Interfaces {
		logging.Debugf("IPAM Add result Interfaces Name: %#v", int.Name)
		logging.Debugf("IPAM Add result Interfaces Mac: %#v", int.Mac)
		logging.Debugf("IPAM Add result Interfaces Sandbox: %#v", int.Sandbox)
	}
	for _, ip := range result.IPs {
		logging.Debugf("IPAM Add result IPs: %v", ip.Version)
		logging.Debugf("IPAM Add result IPs: %v", ip.Interface)
		logging.Debugf("IPAM Add result IPs: %v", ip.Address)
		logging.Debugf("IPAM Add result IPs: %v", ip.Gateway)
	}
	for _, r := range result.Routes {
		logging.Debugf("IPAM Add result Routes: %#v", r.Dst)
		logging.Debugf("IPAM Add result Routes: %#v", r.GW)
	}
	logging.Debugf("IPAM Add result DNS: %#v", result.DNS)

	if len(result.IPs) == 0 {
		return errors.New("IPAM plugin returned missing IP config")
	}
	for _, ipc := range result.IPs {
		// All addresses belong to the ipvlan interface
		ipc.Interface = current.Int(0)
	}

	logging.Debugf("IPAM result interfaces: %#v", result.Interfaces)

	result.Interfaces = []*current.Interface{ipvlanInterface}

	logging.Debugf("IPAM result interfaces: %#v", result.Interfaces)

	logging.Debugf("IPAM Add result CNIVersion: %#v", result.CNIVersion)
	for _, int := range result.Interfaces {
		logging.Debugf("IPAM Add result Interfaces Name: %#v", int.Name)
		logging.Debugf("IPAM Add result Interfaces Mac: %#v", int.Mac)
		logging.Debugf("IPAM Add result Interfaces Sandbox: %#v", int.Sandbox)
	}

	err = netns.Do(func(_ ns.NetNS) error {
		return ipaminteraction.ConfigureIface(args.IfName, result)
	})
	if err != nil {
		return err
	}

	result.DNS = n.DNS

	logging.Debugf("cmd Add finish result: %#v", result)
	logging.Debugf("cmd Add finish result cniVersion: %v", cniVersion)
	logging.Debugf("IPAM Add result CNIVersion: %#v", result.CNIVersion)
	for _, int := range result.Interfaces {
		logging.Debugf("IPAM Add result Interfaces Name: %#v", int.Name)
		logging.Debugf("IPAM Add result Interfaces Mac: %#v", int.Mac)
		logging.Debugf("IPAM Add result Interfaces Sandbox: %#v", int.Sandbox)
	}
	for _, ip := range result.IPs {
		logging.Debugf("IPAM Add result IPs: %v", ip.Version)
		logging.Debugf("IPAM Add result IPs: %v", ip.Interface)
		logging.Debugf("IPAM Add result IPs: %v", ip.Address)
		logging.Debugf("IPAM Add result IPs: %v", ip.Gateway)
	}
	for _, r := range result.Routes {
		logging.Debugf("IPAM Add result Routes: %#v", r.Dst)
		logging.Debugf("IPAM Add result Routes: %#v", r.GW)
	}
	logging.Debugf("IPAM Add result DNS: %#v", result.DNS)

	return types.PrintResult(result, cniVersion)
}

func cmdCheck(args *skel.CmdArgs) error {
	n, _, err := loadConf(args.StdinData, true)
	if err != nil {
		return err
	}
	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	logging.Debugf("cmdCheck: %v, %v, %v", n, netns, n.IPAM.Type)

	if n.IPAM.Type != "" {
		// run the IPAM plugin and get back the config to apply
		err = ipam.ExecCheck(n.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}
	}

	// Parse previous result.
	if n.NetConf.RawPrevResult == nil {
		return logging.Errorf("Required prevResult missing")
	}

	if err := version.ParsePrevResult(&n.NetConf); err != nil {
		return err
	}

	result, err := current.NewResultFromResult(n.PrevResult)
	if err != nil {
		return err
	}

	var contMap current.Interface
	// Find interfaces for names whe know, ipvlan inside container
	for _, intf := range result.Interfaces {
		if args.IfName == intf.Name {
			if args.Netns == intf.Sandbox {
				contMap = *intf
				continue
			}
		}
	}

	// The namespace must be the same as what was configured
	if args.Netns != contMap.Sandbox {
		return logging.Errorf("Sandbox in prevResult %s doesn't match configured netns: %s",
			contMap.Sandbox, args.Netns)
	}

	m, err := netlink.LinkByName(n.Master)
	if err != nil {
		return logging.Errorf("failed to lookup master %q: %v", n.Master, err)
	}

	// Check prevResults for ips, routes and dns against values found in the container
	if err := netns.Do(func(_ ns.NetNS) error {

		// Check interface against values found in the container
		err := validateCniContainerInterface(contMap, m.Attrs().Index, n.Mode)
		if err != nil {
			return err
		}

		err = ip.ValidateExpectedInterfaceIPs(args.IfName, result.IPs)
		if err != nil {
			return err
		}

		err = ip.ValidateExpectedRoute(result.Routes)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func cmdDel(args *skel.CmdArgs) error {
	//args.IfName = "eth0"

	n, _, err := loadConf(args.StdinData, false)
	if err != nil {
		return err
	}

	logging.Debugf("cmdDel args.Args: %#v", args.Args)

	/*
		logging.Debugf("cmdDel args.Args: %#v", args.Args)

		ipamConf, confVersion, err := ipaminteraction.LoadIPAMConfig(args.StdinData, args.Args)
		if err != nil {
			return err
		}

		logging.Debugf("/n")
		logging.Debugf("cmdDel ipamConf Name: %v", ipamConf.Name)
		logging.Debugf("cmdDel ipamConf Type: %v", ipamConf.Type)
		for _, r := range ipamConf.Routes {
			logging.Debugf("cmdDel ipamConf Route: %v", r)
		}
		for _, a := range ipamConf.Addresses {
			logging.Debugf("cmdDel ipamConf Address AddressStr: %v", a.AddressStr)
			logging.Debugf("cmdDel ipamConf Address Gateway: %#v", a.Gateway)
			logging.Debugf("cmdDel ipamConf Address Address: %#v", a.AddressStr)
			logging.Debugf("cmdDel ipamConf Address Version: %v", a.Version)
		}
		logging.Debugf("/n")

		logging.Debugf("/n")
		logging.Debugf("cmdDel ipamConf: %#v", ipamConf)
		logging.Debugf("cmdDel ipam conf version: %v", confVersion)
		logging.Debugf("/n")

		logging.Debugf("/n")
		logging.Debugf("cmdDel Conf: %#v", n)
		logging.Debugf("cmdDel Netns: %v", args.Netns)
		logging.Debugf("/n")
	*/

	// On chained invocation, IPAM block can be empty
	if n.IPAM.Type != "" {
		err = ipam.ExecDel(n.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}
	}

	if args.Netns == "" {
		return nil
	}

	// There is a netns so try to clean up. Delete can be called multiple times
	// so don't return an error if the device is already removed.
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		if err := ip.DelLinkByName(args.IfName); err != nil {
			if err != ip.ErrLinkNotFound {
				return err
			}
		}
		return nil
	})

	return err
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("ipvlan-if"))
}

func validateCniContainerInterface(intf current.Interface, masterIndex int, modeExpected string) error {

	var link netlink.Link
	var err error

	if intf.Name == "" {
		return logging.Errorf("Container interface name missing in prevResult: %v", intf.Name)
	}
	link, err = netlink.LinkByName(intf.Name)
	if err != nil {
		return logging.Errorf("Container Interface name in prevResult: %s not found", intf.Name)
	}
	if intf.Sandbox == "" {
		return logging.Errorf("Error: Container interface %s should not be in host namespace", link.Attrs().Name)
	}

	ipv, isIPVlan := link.(*netlink.IPVlan)
	if !isIPVlan {
		return logging.Errorf("Error: Container interface %s not of type ipvlan", link.Attrs().Name)
	}

	mode, err := modeFromString(modeExpected)
	if ipv.Mode != mode {
		currString, err := modeToString(ipv.Mode)
		if err != nil {
			return err
		}
		confString, err := modeToString(mode)
		if err != nil {
			return err
		}
		return logging.Errorf("Container IPVlan mode %s does not match expected value: %s", currString, confString)
	}

	if intf.Mac != "" {
		if intf.Mac != link.Attrs().HardwareAddr.String() {
			return logging.Errorf("Interface %s Mac %s doesn't match container Mac: %s", intf.Name, intf.Mac, link.Attrs().HardwareAddr)
		}
	}

	return nil
}
