//go:build linux

package redirect

import (
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"

	"go4.org/netipx"
)

func (t *TProxy) createIPSets() error {
	setNameIncludeMAC := t.tableName + "-include-mac"
	setNameExcludeMAC := t.tableName + "-exclude-mac"
	if len(t.IncludeMAC) > 0 {
		err := t.createIPSet(setNameIncludeMAC, "hash:mac")
		if err != nil {
			return err
		}
		err = t.fillIPSet(setNameIncludeMAC,
			mapToAny(t.IncludeMAC))
		if err != nil {
			return err
		}
	}
	if len(t.ExcludeMAC) > 0 {
		err := t.createIPSet(setNameExcludeMAC, "hash:mac")
		if err != nil {
			return err
		}
		err = t.fillIPSet(setNameExcludeMAC,
			mapToAny(t.ExcludeMAC))
		if err != nil {
			return err
		}
	}
	if t.enableIPv4 {
		err := t.createIPSetsForFamily(false)
		if err != nil {
			return err
		}
	}
	if t.enableIPv6 {
		err := t.createIPSetsForFamily(true)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *TProxy) createIPSetsForFamily(isIPv6 bool) error {
	var matchAllAddress string
	var unspecAddress []string
	setNameUnspec := t.tableName + "-unspec"
	setNameLocal := t.tableName + "-local"
	setNameIncludeAddress := t.tableName + "-include-address"
	setNameExcludeAddress := t.tableName + "-exclude-address"
	setNameIncludeInterface := t.tableName + "-include-interface"
	setNameExcludeInterface := t.tableName + "-exclude-interface"
	if !isIPv6 {
		setNameUnspec += "-v4"
		setNameLocal += "-v4"
		setNameIncludeAddress += "-v4"
		setNameExcludeAddress += "-v4"
		setNameIncludeInterface += "-v4"
		setNameExcludeInterface += "-v4"
		matchAllAddress = "0.0.0.0/0"
		unspecAddress = append(unspecAddress, "0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32")
	} else {
		setNameUnspec += "-v6"
		setNameLocal += "-v6"
		setNameIncludeAddress += "-v6"
		setNameExcludeAddress += "-v6"
		setNameIncludeInterface += "-v6"
		setNameExcludeInterface += "-v6"
		matchAllAddress = "::/0"
		unspecAddress = append(unspecAddress, "::/128", "::1/128", "fe80::/10")
	}
	if !t.hasAddrType {
		err := t.createIPSetForFamily(setNameUnspec, "hash:net", isIPv6)
		if err != nil {
			return err
		}
		err = t.fillIPSet(setNameUnspec, mapToAny(unspecAddress))
		if err != nil {
			return err
		}
		err = t.createIPSetForFamily(setNameLocal, "hash:ip", isIPv6)
		if err != nil {
			return err
		}
		err = t.fillIPSet(setNameLocal, common.FlatMap(t.networkManager.NetworkInterfaces(),
			func(inter adapter.NetworkInterface) []any {
				return mapToAny(common.Filter(inter.Addresses, func(net netip.Prefix) bool {
					return net.Addr().Is6() == isIPv6
				}))
			}))
		if err != nil {
			return err
		}
	}
	if len(t.RouteAddress) > 0 || len(t.RouteAddressSet) > 0 {
		err := t.createIPSetForFamily(setNameIncludeAddress, "hash:net", isIPv6)
		if err != nil {
			return err
		}
		err = t.fillIPSet(setNameIncludeAddress, mapToAny(common.Filter(t.RouteAddress,
			func(net netip.Prefix) bool {
				return net.Addr().Is6() == isIPv6
			})))
		if err != nil {
			return err
		}
		err = t.fillIPSet(setNameIncludeAddress, common.FlatMap(t.routeAddressSet,
			func(set *netipx.IPSet) []any {
				return mapToAny(common.Filter(set.Prefixes(), func(net netip.Prefix) bool {
					return net.Addr().Is6() == isIPv6
				}))
			}))
		if err != nil {
			return err
		}
	}
	if len(t.RouteExcludeAddress) > 0 || len(t.RouteExcludeAddressSet) > 0 {
		err := t.createIPSetForFamily(setNameExcludeAddress, "hash:net", isIPv6)
		if err != nil {
			return err
		}
		err = t.fillIPSet(setNameExcludeAddress, mapToAny(common.Filter(t.RouteExcludeAddress,
			func(net netip.Prefix) bool {
				return net.Addr().Is6() == isIPv6
			})))
		if err != nil {
			return err
		}
		err = t.fillIPSet(setNameExcludeAddress, common.FlatMap(t.routeExcludeAddressSet,
			func(set *netipx.IPSet) []any {
				return mapToAny(common.Filter(set.Prefixes(), func(net netip.Prefix) bool {
					return net.Addr().Is6() == isIPv6
				}))
			}))
		if err != nil {
			return err
		}
	}
	if len(t.IncludeInterface) > 0 {
		err := t.createIPSetForFamily(setNameIncludeInterface, "hash:net,iface", isIPv6)
		if err != nil {
			return err
		}
		err = t.fillIPSet(setNameIncludeInterface, common.Map(t.IncludeInterface, func(iface string) any {
			return matchAllAddress + "," + iface
		}))
		if err != nil {
			return err
		}
	}
	if len(t.ExcludeInterface) > 0 {
		err := t.createIPSetForFamily(setNameExcludeInterface, "hash:net,iface", isIPv6)
		if err != nil {
			return err
		}
		err = t.fillIPSet(setNameExcludeInterface, common.Map(t.ExcludeInterface, func(iface string) any {
			return matchAllAddress + "," + iface
		}))
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *TProxy) iptablesUpdateLocalAddressSetForFamily(isIPv6 bool) error {
	setName := t.tableName + "-local"
	if !isIPv6 {
		setName += "-v4"
	} else {
		setName += "-v6"
	}
	err := t.flushIPSet(setName)
	if err != nil {
		return err
	}
	err = t.fillIPSet(setName, common.FlatMap(t.networkManager.NetworkInterfaces(),
		func(inter adapter.NetworkInterface) []any {
			return mapToAny(common.Filter(inter.Addresses, func(net netip.Prefix) bool {
				return net.Addr().Is6() == isIPv6
			}))
		}))
	if err != nil {
		return err
	}
	return nil
}

func (t *TProxy) iptablesUpdateRouteAddressSet() {
	if !t.hasIPSet {
		return
	}
	if t.enableIPv4 {
		t.iptablesUpdateRouteAddressSetForFamily(false)
	}
	if t.enableIPv6 {
		t.iptablesUpdateRouteAddressSetForFamily(true)
	}
}

func (t *TProxy) iptablesUpdateRouteExcludeAddressSet() {
	if t.enableIPv4 {
		t.iptablesUpdateRouteExcludeAddressSetForFamily(false)
	}
	if t.enableIPv6 {
		t.iptablesUpdateRouteExcludeAddressSetForFamily(true)
	}
}

func (t *TProxy) iptablesUpdateRouteAddressSetForFamily(isIPv6 bool) error {
	if len(t.RouteAddress) == 0 && len(t.RouteAddressSet) == 0 {
		return nil
	}
	setName := t.tableName + "-include-address"
	if !isIPv6 {
		setName += "-v4"
	} else {
		setName += "-v6"
	}
	err := t.flushIPSet(setName)
	if err != nil {
		return err
	}
	err = t.fillIPSet(setName, mapToAny(common.Filter(t.RouteAddress,
		func(net netip.Prefix) bool {
			return net.Addr().Is6() == isIPv6
		})))
	if err != nil {
		return err
	}
	err = t.fillIPSet(setName, common.FlatMap(t.routeAddressSet,
		func(set *netipx.IPSet) []any {
			return mapToAny(common.Filter(set.Prefixes(), func(net netip.Prefix) bool {
				return net.Addr().Is6() == isIPv6
			}))
		}))
	if err != nil {
		return err
	}
	return nil
}

func (t *TProxy) iptablesUpdateRouteExcludeAddressSetForFamily(isIPv6 bool) error {
	if len(t.RouteExcludeAddress) == 0 && len(t.RouteExcludeAddressSet) == 0 {
		return nil
	}
	setName := t.tableName + "-exclude-address"
	if !isIPv6 {
		setName += "-v4"
	} else {
		setName += "-v6"
	}
	err := t.flushIPSet(setName)
	if err != nil {
		return err
	}
	err = t.fillIPSet(setName, mapToAny(common.Filter(t.RouteExcludeAddress,
		func(net netip.Prefix) bool {
			return net.Addr().Is6() == isIPv6
		})))
	if err != nil {
		return err
	}
	err = t.fillIPSet(setName, common.FlatMap(t.routeExcludeAddressSet,
		func(set *netipx.IPSet) []any {
			return mapToAny(common.Filter(set.Prefixes(), func(net netip.Prefix) bool {
				return net.Addr().Is6() == isIPv6
			}))
		}))
	if err != nil {
		return err
	}
	return nil
}

func (t *TProxy) cleanupIPSets() {
	setNameIncludeMAC := t.tableName + "-include-mac"
	setNameExcludeMAC := t.tableName + "-exclude-mac"
	// include mac set
	t.flushIPSet(setNameIncludeMAC)
	t.destroyIPSet(setNameIncludeMAC)

	// exclude mac set
	t.flushIPSet(setNameExcludeMAC)
	t.destroyIPSet(setNameExcludeMAC)
	if t.enableIPv4 {
		t.cleanupIPSetsForFamily(false)
	}
	if t.enableIPv6 {
		t.cleanupIPSetsForFamily(true)
	}
}

func (t *TProxy) cleanupIPSetsForFamily(isIPv6 bool) {
	setNameUnspec := t.tableName + "-unspec"
	setNameLocal := t.tableName + "-local"
	setNameIncludeAddress := t.tableName + "-include-address"
	setNameExcludeAddress := t.tableName + "-exclude-address"
	setNameIncludeInterface := t.tableName + "-include-interface"
	setNameExcludeInterface := t.tableName + "-exclude-interface"
	if !isIPv6 {
		setNameUnspec += "-v4"
		setNameLocal += "-v4"
		setNameIncludeAddress += "-v4"
		setNameExcludeAddress += "-v4"
		setNameIncludeInterface += "-v4"
		setNameExcludeInterface += "-v4"
	} else {
		setNameUnspec += "-v6"
		setNameLocal += "-v6"
		setNameIncludeAddress += "-v6"
		setNameExcludeAddress += "-v6"
		setNameIncludeInterface += "-v6"
		setNameExcludeInterface += "-v6"
	}
	// unspec address set
	t.flushIPSet(setNameUnspec)
	t.destroyIPSet(setNameUnspec)

	// local address set
	t.flushIPSet(setNameLocal)
	t.destroyIPSet(setNameLocal)

	// include address set
	t.flushIPSet(setNameIncludeAddress)
	t.destroyIPSet(setNameIncludeAddress)

	// exclude address set
	t.flushIPSet(setNameExcludeAddress)
	t.destroyIPSet(setNameExcludeAddress)

	// include interface set
	t.flushIPSet(setNameIncludeInterface)
	t.destroyIPSet(setNameIncludeInterface)

	// exclude interface set
	t.flushIPSet(setNameExcludeInterface)
	t.destroyIPSet(setNameExcludeInterface)
}

func (t *TProxy) createIPSet(setName string, setType string) error {
	return t.runIPSet("create", setName, setType)
}

func (t *TProxy) createIPSetForFamily(setName string, setType string, isIPv6 bool) error {
	if !isIPv6 {
		return t.runIPSet("create", setName, setType, "family", "inet")
	} else {
		return t.runIPSet("create", setName, setType, "family", "inet6")
	}
}

func (t *TProxy) flushIPSet(setName string) error {
	return t.runIPSet("flush", setName)
}

func (t *TProxy) destroyIPSet(setName string) error {
	return t.runIPSet("destroy", setName)
}

func (t *TProxy) fillIPSet(setName string, items []any) error {
	for _, item := range items {
		err := t.runIPSet("add", setName, item)
		if err != nil {
			return err
		}
	}
	return nil
}
