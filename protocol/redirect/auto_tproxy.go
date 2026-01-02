//go:build linux

package redirect

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	"go4.org/netipx"
)

type autoTProxyOptions struct {
	*option.AutoTProxyOptions
	listen                      M.Socksaddr
	network                     []string
	userId                      int
	groupId                     int
	androidSu                   bool
	suPath                      string
	enableIPv4                  bool
	enableIPv6                  bool
	tableName                   string
	hasIPSet                    bool
	hasAddrType                 bool
	useNFTables                 bool
	networkManager              adapter.NetworkManager
	routeRuleSet                []adapter.RuleSet
	routeAddressSet             []*netipx.IPSet
	routeRuleSetCallback        []*list.Element[adapter.RuleSetUpdateCallback]
	routeExcludeRuleSet         []adapter.RuleSet
	routeExcludeAddressSet      []*netipx.IPSet
	routeExcludeRuleSetCallback []*list.Element[adapter.RuleSetUpdateCallback]
	interfaceAddress            []netip.Addr
	loIndex                     int
}

func newAutoTProxy(ctx context.Context, router adapter.Router, options *option.AutoTProxyOptions, network []string, listen M.Socksaddr) (*autoTProxyOptions, error) {
	if options == nil || !options.Enabled {
		return nil, nil
	}
	disableNFTables, dErr := strconv.ParseBool(os.Getenv("DISABLE_NFTABLES"))
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	var routeRuleSet, routeExcludeRuleSet []adapter.RuleSet
	for _, routeAddressSet := range options.RouteAddressSet {
		ruleSet, loaded := router.RuleSet(routeAddressSet)
		if !loaded {
			return nil, E.New("parse route_address_set: rule-set not found: ", routeAddressSet)
		}
		routeRuleSet = append(routeRuleSet, ruleSet)
	}
	for _, routeExcludeAddressSet := range options.RouteExcludeAddressSet {
		ruleSet, loaded := router.RuleSet(routeExcludeAddressSet)
		if !loaded {
			return nil, E.New("parse route_exclude_address_set: rule-set not found: ", routeExcludeAddressSet)
		}
		routeExcludeRuleSet = append(routeExcludeRuleSet, ruleSet)
	}
	if options.TProxyMark == 0 {
		options.TProxyMark = 2025
	}
	if options.TProxyTableId == 0 {
		options.TProxyTableId = 100
	}
	return &autoTProxyOptions{
		AutoTProxyOptions:   options,
		listen:              listen,
		network:             common.Map(network, func(it string) string { return strings.ToLower(it) }),
		userId:              os.Getuid(),
		groupId:             os.Getgid(),
		tableName:           "sing-box",
		enableIPv4:          listen.Addr.IsUnspecified() || listen.IsIPv4(),
		enableIPv6:          listen.Addr.IsUnspecified() || listen.IsIPv6(),
		useNFTables:         false && runtime.GOOS != "android" && (dErr != nil || !disableNFTables),
		networkManager:      networkManager,
		routeRuleSet:        routeRuleSet,
		routeExcludeRuleSet: routeExcludeRuleSet,
	}, nil
}

func (t *TProxy) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if t.autoTProxyOptions == nil || !t.AutoTProxyOptions.Enabled {
		return t.listener.Start()
	}
	t.routeAddressSet = common.FlatMap(t.routeRuleSet, adapter.RuleSet.ExtractIPSet)
	for _, routeRuleSet := range t.routeRuleSet {
		ipSets := routeRuleSet.ExtractIPSet()
		if len(ipSets) == 0 {
			t.logger.Warn("route_address_set: no destination IP CIDR rules found in rule-set: ", routeRuleSet.Name())
		}
		routeRuleSet.IncRef()
		t.routeAddressSet = append(t.routeAddressSet, ipSets...)
		t.routeRuleSetCallback = append(t.routeRuleSetCallback, routeRuleSet.RegisterCallback(t.updateRouteAddressSet))
	}
	t.routeExcludeAddressSet = common.FlatMap(t.routeExcludeRuleSet, adapter.RuleSet.ExtractIPSet)
	for _, routeExcludeRuleSet := range t.routeExcludeRuleSet {
		ipSets := routeExcludeRuleSet.ExtractIPSet()
		if len(ipSets) == 0 {
			t.logger.Warn("route_address_set: no destination IP CIDR rules found in rule-set: ", routeExcludeRuleSet.Name())
		}
		routeExcludeRuleSet.IncRef()
		t.routeExcludeAddressSet = append(t.routeExcludeAddressSet, ipSets...)
		t.routeExcludeRuleSetCallback = append(t.routeExcludeRuleSetCallback, routeExcludeRuleSet.RegisterCallback(t.updateRouteExcludeAddressSet))
	}
	err := t.listener.Start()
	if err != nil {
		return err
	}
	err = t.startAutoTProxy()
	if err != nil {
		return err
	}
	t.routeAddressSet = nil
	t.routeExcludeAddressSet = nil
	return nil
}

func (t *TProxy) Close() error {
	if t.autoTProxyOptions != nil && t.autoTProxyOptions.Enabled {
		t.stopAutoTProxy()
	}
	err := t.listener.Close()
	if err != nil {
		return err
	}
	return nil
}

func (t *TProxy) startAutoTProxy() error {
	var err error
	if runtime.GOOS == "android" {
		if t.userId != 0 {
			t.androidSu = true
			for _, suPath := range []string{
				"su",
				"/system/bin/su",
			} {
				t.suPath, err = exec.LookPath(suPath)
				if err == nil {
					break
				}
			}
			if err != nil {
				return E.Extend(E.Cause(err, "root permission is required for auto redirect"), os.Getenv("PATH"))
			}
		}
	} else {
		if t.useNFTables {
			err = t.initializeNFTables()
			if err != nil {
				return E.Cause(err, "missing nftables support")
			}
		}
	}
	if !t.useNFTables {
		if t.enableIPv4 {
			err = t.runIPTables(false, "-h")
			if err != nil {
				return E.Cause(err, "iptables is required")
			}
		}
		if t.enableIPv6 {
			err = t.runIPTables(true, "-h")
			if err != nil {
				if t.listen.Addr != netip.IPv6Unspecified() {
					return E.Cause(err, "ip6tables is required")
				} else {
					t.logger.Error("device has no ip6tables nat support: ", err)
					t.enableIPv6 = false
				}
			}
		}
	}
	if t.hasAddrType = t.checkHasAddrType(); !t.hasAddrType {
		t.interfaceAddress = common.FlatMap(t.networkManager.NetworkInterfaces(), func(inter adapter.NetworkInterface) []netip.Addr {
			return common.Map(inter.Addresses, func(net netip.Prefix) netip.Addr { return net.Addr() })
		})
	}
	t.hasIPSet = t.checkHasIPSet()
	if t.useNFTables {
		// t.cleanupNFTables()
		// err = t.setupNFTables()
		// if err != nil {
		// 	return err
		// }
	} else {
		t.cleanupIPTables()
		err = t.setupIPTables()
		if err != nil {
			return err
		}
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	t.loIndex = lo.Attrs().Index
	t.cleanupNetlink()
	return t.setupNetlink()
}

func (t *TProxy) stopAutoTProxy() error {
	t.cleanupNetlink()
	if t.useNFTables {
		// t.cleanupNFTables()
	} else {
		t.cleanupIPTables()
	}
	return nil
}

func (t *TProxy) checkHasAddrType() bool {
	// if runtime.GOOS == "android" {
	// 	return false
	// }
	if err := t.runShell("lsmod", "|", "grep xt_addrtype"); err == nil {
		return true
	}
	if err := t.runIPTables(!t.enableIPv4, "-m addrtype", "--help", "2>&1", "|", "grep -E 'Warning|(Couldn't load)'"); err != nil {
		return true
	}
	return false
}

func (t *TProxy) checkHasIPSet() bool {
	if err := t.runIPSet("-v"); err != nil {
		return false
	}
	if err := t.runShell("lsmod", "|", "grep xt_set"); err == nil {
		return true
	}
	if err := t.runIPTables(!t.enableIPv4, "-m set", "--help", "2>&1", "|", "grep -E 'Warning|(Couldn't load)'"); err != nil {
		return true
	}
	return false
}

// todo: use netlink

// func (t *TProxy) getNetlinkRoute(isIPv6 bool) *netlink.Route {
// 	route := &netlink.Route{
// 		Table:     t.TProxyTableId,
// 		LinkIndex: t.loIndex,
// 		Scope:     netlink.SCOPE_UNIVERSE,
// 		Type:      unix.RTN_LOCAL,
// 	}
// 	if !isIPv6 {
// 		route.Family = netlink.FAMILY_V4
// 		route.Dst = &net.IPNet{
// 			IP:   net.IPv4zero,
// 			Mask: net.CIDRMask(0, 32),
// 		}
// 	} else {
// 		route.Family = netlink.FAMILY_V6
// 		route.Dst = &net.IPNet{
// 			IP:   net.IPv6zero,
// 			Mask: net.CIDRMask(0, 128),
// 		}
// 	}
// 	return route
// }

// func (t *TProxy) getNetlinkRule(isIPv6 bool) *netlink.Rule {
// 	rule := netlink.NewRule()
// 	rule.Priority = t.TProxyTableId
// 	rule.Table = t.TProxyTableId
// 	rule.Mark = t.TProxyMark
// 	rule.Mask = 0xffffffff
// 	if !isIPv6 {
// 		rule.Family = netlink.FAMILY_V4
// 	} else {
// 		rule.Family = netlink.FAMILY_V6
// 	}
// 	return rule
// }

func (t *TProxy) setupNetlink() error {
	if t.enableIPv4 {
		err := t.setupNetlinkForFamily(false)
		if err != nil {
			return err
		}
	}
	if t.enableIPv6 {
		err := t.setupNetlinkForFamily(true)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *TProxy) setupNetlinkForFamily(isIPv6 bool) error {
	err := t.runIPRule(isIPv6, "add", "fwmark", t.TProxyMark, "table", t.TProxyTableId, "pref", t.TProxyTableId)
	if err != nil {
		return err
	}
	err = t.runIPRoute(isIPv6, "add", "local", "default", "dev", "lo", "table", t.TProxyTableId)
	if err != nil {
		return err
	}
	return nil
}

func (t *TProxy) cleanupNetlink() {
	if t.enableIPv4 {
		t.cleanupNetlinkForFamily(false)
	}
	if t.enableIPv6 {
		t.cleanupNetlinkForFamily(true)
	}
}

func (t *TProxy) cleanupNetlinkForFamily(isIPv6 bool) {
	t.runIPRule(isIPv6, "del", "fwmark", t.TProxyMark, "table", t.TProxyTableId, "pref", t.TProxyTableId)
	t.runIPRoute(isIPv6, "flush", "table", t.TProxyTableId)
}

func (t *TProxy) updateRouteAddressSet(it adapter.RuleSet) {
	t.routeAddressSet = common.FlatMap(t.routeRuleSet, adapter.RuleSet.ExtractIPSet)
	if t.useNFTables {
		// t.nftablesUpdateRouteAddressSet()
	} else {
		t.iptablesUpdateRouteAddressSet()
	}
	t.routeAddressSet = nil
}

func (t *TProxy) updateRouteExcludeAddressSet(it adapter.RuleSet) {
	t.routeAddressSet = common.FlatMap(t.routeRuleSet, adapter.RuleSet.ExtractIPSet)
	if t.useNFTables {
		// t.nftablesUpdateRouteExcludeAddressSet()
	} else {
		t.iptablesUpdateRouteExcludeAddressSet()
	}
	t.routeAddressSet = nil
}

func (t *TProxy) InterfaceUpdated() {
	if t.autoTProxyOptions == nil || !t.autoTProxyOptions.Enabled || t.hasAddrType {
		return
	}
	t.interfaceAddress = common.FlatMap(t.networkManager.NetworkInterfaces(), func(inter adapter.NetworkInterface) []netip.Addr {
		return common.Map(inter.Addresses, func(net netip.Prefix) netip.Addr { return net.Addr() })
	})
	if t.useNFTables {
	} else {
		t.iptablesInterfaceUpdate()
	}
}

func (t *TProxy) runShell(commands ...any) error {
	commandArray := common.Filter(
		strings.Split(strings.Join(F.MapToString(commands), " "), " "),
		func(it string) bool { return len(it) > 0 },
	)
	commandStr := strings.Join(commandArray, " ")
	var command *exec.Cmd
	if t.androidSu {
		command = exec.Command(t.suPath, "-c", commandStr)
	} else {
		command = exec.Command("sh", "-c", commandStr)
	}
	combinedOutput, err := command.CombinedOutput()
	if err != nil {
		return E.Extend(err, F.ToString(commandStr, ": ", string(combinedOutput)))
	}
	return nil
}

func (t *TProxy) runIPRule(isIPv6 bool, commands ...any) error {
	return t.runIP(isIPv6, append([]any{"rule"}, commands...)...)
}

func (t *TProxy) runIPRoute(isIPv6 bool, commands ...any) error {
	return t.runIP(isIPv6, append([]any{"route"}, commands...)...)
}

func (t *TProxy) runIP(isIPv6 bool, commands ...any) error {
	var ip string
	if !isIPv6 {
		ip = "ip"
	} else {
		ip = "ip -6"
	}
	return t.runShell(append([]any{ip}, commands...)...)
}

func (t *TProxy) runIPTables(isIPv6 bool, commands ...any) error {
	var iptables string
	if !isIPv6 {
		iptables = "iptables"
	} else {
		iptables = "ip6tables"
	}
	return t.runShell(append([]any{iptables}, commands...)...)
}

func (t *TProxy) runIPSet(commands ...any) error {
	return t.runShell(append([]any{"ipset"}, commands...)...)
}
