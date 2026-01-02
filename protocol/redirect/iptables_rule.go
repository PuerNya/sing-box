//go:build linux

package redirect

import (
	"fmt"
	"net/netip"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

func (t *TProxy) setupIPTablesForFamily(isIPv6 bool) error {
	var unspecAddress []string
	tableNameLocal := t.tableName + "-local"
	tableNameExternal := t.tableName + "-external"
	setNameUnspec := t.tableName + "-unspec"
	setNameLocal := t.tableName + "-local"
	setNameIncludeAddress := t.tableName + "-include-address"
	setNameExcludeAddress := t.tableName + "-exclude-address"
	setNameIncludeInterface := t.tableName + "-include-interface"
	setNameExcludeInterface := t.tableName + "-exclude-interface"
	setNameIncludeMAC := t.tableName + "-include-interface"
	setNameExcludeMAC := t.tableName + "-exclude-interface"
	includeAddress := common.Filter(t.RouteAddress, func(it netip.Prefix) bool { return isIPv6 == it.Addr().Is6() })
	excludeAddress := common.Filter(t.RouteExcludeAddress, func(it netip.Prefix) bool { return isIPv6 == it.Addr().Is6() })
	interfaceAddress := common.Filter(t.interfaceAddress, func(it netip.Addr) bool { return it.Is6() == isIPv6 })
	if !isIPv6 {
		setNameUnspec += "-v4"
		setNameLocal += "-v4"
		setNameIncludeAddress += "-v4"
		setNameExcludeAddress += "-v4"
		setNameIncludeInterface += "-v4"
		setNameExcludeInterface += "-v4"
		unspecAddress = append(unspecAddress, "0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32")
	} else {
		setNameUnspec += "-v6"
		setNameLocal += "-v6"
		setNameIncludeAddress += "-v6"
		setNameExcludeAddress += "-v6"
		setNameIncludeInterface += "-v6"
		setNameExcludeInterface += "-v6"
		unspecAddress = append(unspecAddress, "::/128", "::1/128", "fe80::/10")
	}

	// LOCAL
	err := t.createIPTablesTable(isIPv6, tableNameLocal)
	if err != nil {
		return err
	}
	// bypass reply message
	err = t.setupIPTablesExcludeMatchers(isIPv6, tableNameLocal, "-m conntrack", "--ctdir REPLY")
	if err != nil {
		return err
	}
	// mark already tproxy socket
	err = t.setupIPTablesMarkMatchers(isIPv6, tableNameLocal, "-m socket", "--transparent")
	if err != nil {
		return err
	}
	// accept already tproxy socket
	err = t.setupIPTablesAcceptMatchers(isIPv6, tableNameLocal, "-m socket", "--transparent")
	if err != nil {
		return err
	}
	// bypass all socket
	err = t.setupIPTablesExcludeMatchers(isIPv6, tableNameLocal, "-m socket")
	if err != nil {
		return err
	}
	// bypass self with uid && gid
	err = t.setupIPTablesExcludeMatchers(isIPv6, tableNameLocal,
		"-m owner --uid-owner", t.userId, "--gid-owner", t.groupId)
	if err != nil {
		return err
	}
	// bypass uid blacklist
	if len(t.ExcludeUID) > 0 {
		err = t.setupIPTablesExcludeCommands(isIPv6, tableNameLocal,
			newCommands("-m owner --uid-owner", t.ExcludeUID))
		if err != nil {
			return err
		}
	}
	// bypass gid blacklist
	if len(t.ExcludeGID) > 0 {
		err = t.setupIPTablesExcludeCommands(isIPv6, tableNameLocal,
			newCommands("-m owner --gid-owner", t.ExcludeGID))
		if err != nil {
			return err
		}
	}
	// bypass uidgid blacklist
	if len(t.ExcludeUIDGID) > 0 {
		err = t.setupIPTablesExcludeCommands(isIPv6, tableNameLocal,
			newCommands("-m owner", common.Map(t.ExcludeUIDGID, func(it option.UidGid) string {
				return fmt.Sprintf("--uid-owner %v --gid-owner %v", it.Uid, it.Gid)
			})))
		if err != nil {
			return err
		}
	}
	// bypass mark blacklist
	if len(t.ExcludeMark) > 0 {
		err = t.setupIPTablesExcludeCommands(isIPv6, tableNameLocal,
			newCommands("-m mark --mark", t.ExcludeMark))
		if err != nil {
			return err
		}
	}
	// bypass unpsec/multicast/local address
	if t.hasAddrType {
		// bypass unpsec/multicast/local address by addrtype
		err = t.setupIPTablesExcludeCommands(isIPv6, tableNameLocal,
			newCommands("-m addrtype --dst-type", []string{"UNSPEC", "MULTICAST", "LOCAL"}))
		if err != nil {
			return err
		}
	} else if t.hasIPSet {
		// bypass unpsec/multicast/local address by ipset
		err = t.setupIPTablesExcludeMatchers(isIPv6, tableNameLocal,
			"-m set --match-set", setNameUnspec, "dst")
		if err != nil {
			return err
		}
		// bypass interface address by ipset
		err = t.setupIPTablesExcludeMatchers(isIPv6, tableNameLocal,
			"-m set --match-set", setNameLocal, "dst")
		if err != nil {
			return err
		}
	} else {
		// bypass unpsec/multicast/local address
		err = t.setupIPTablesExcludeCommands(isIPv6, tableNameLocal,
			newCommands("-d", unspecAddress))
		if err != nil {
			return err
		}
		// bypass interface address
		err = t.setupIPTablesExcludeCommands(isIPv6, tableNameLocal,
			newCommands("-d", interfaceAddress))
		if err != nil {
			return err
		}
	}
	// bypass address blacklist, except dns
	if t.hasIPSet {
		if len(t.RouteExcludeAddress) > 0 || len(t.RouteExcludeAddressSet) > 0 {
			// bypass address blacklist by ipset, except dns
			err = t.setupIPTablesExcludeExceptDNSMatchers(isIPv6, tableNameLocal,
				"-m set --match-set", setNameExcludeAddress, "dst")
			if err != nil {
				return err
			}
		}
	} else if len(t.RouteExcludeAddress) > 0 {
		// bypass address blacklist, except dns
		err = t.setupIPTablesExcludeExceptDNSCommands(isIPv6, tableNameLocal,
			newCommands("-d", excludeAddress))
		if err != nil {
			return err
		}
	}
	// set uid/gid/uidgid whitelist
	commands := emptyCommands
	if len(t.IncludeUID) > 0 || len(t.IncludeGID) > 0 || len(t.IncludeUIDGID) > 0 {
		var matchers []any
		// set uid whitelist
		if len(t.IncludeUID) > 0 {
			matchers = append(matchers, common.Map(t.IncludeUID, func(it option.IdRange) string {
				return fmt.Sprintf("--uid-owner %v", it)
			}))
		}
		// set gid whitelist
		if len(t.IncludeGID) > 0 {
			matchers = append(matchers, common.Map(t.IncludeGID, func(it option.IdRange) string {
				return fmt.Sprintf("--gid-owner %v", it)
			}))
		}
		// set uidgid whitelist
		if len(t.IncludeUIDGID) > 0 {
			matchers = append(matchers, common.Map(t.IncludeUIDGID, func(it option.UidGid) string {
				return fmt.Sprintf("--uid-owner %v --gid-owner %v", it.Uid, it.Gid)
			}))
		}
		commands = fillCommands(commands, "-m owner", matchers)
	}
	// mark all tcp && udp
	if len(t.RouteAddress) == 0 && (!t.hasIPSet || len(t.RouteAddressSet) == 0) {
		err = t.setupIPTablesMarkCommands(isIPv6, tableNameLocal, commands)
		if err != nil {
			return err
		}
	} else {
		// mark all tcp && udp dns
		err = t.setupIPTablesMarkDNSCommands(isIPv6, tableNameLocal, commands)
		if err != nil {
			return err
		}
		if t.hasIPSet {
			// mark address whitelist by ipset
			err = t.setupIPTablesMarkMatchers(isIPv6, tableNameLocal,
				"-m set --match-set", setNameIncludeAddress, "dst")
			if err != nil {
				return err
			}
		} else {
			// mark address whitelist
			err = t.setupIPTablesMarkCommands(isIPv6, tableNameLocal,
				fillCommands(commands, "-d", includeAddress))
			if err != nil {
				return err
			}
		}
	}
	err = t.setupIPTablesMatchers(isIPv6, "OUTPUT", "-j", tableNameLocal)
	if err != nil {
		return err
	}

	// EXTERNAL
	err = t.createIPTablesTable(isIPv6, tableNameExternal)
	if err != nil {
		return err
	}
	// bypass reply message
	err = t.setupIPTablesExcludeMatchers(isIPv6, tableNameExternal, "-m conntrack", "--ctdir REPLY")
	if err != nil {
		return err
	}
	// mark already tproxy socket
	err = t.setupIPTablesMarkMatchers(isIPv6, tableNameExternal, "-m socket", "--transparent")
	if err != nil {
		return err
	}
	// accept already tproxy socket
	err = t.setupIPTablesAcceptMatchers(isIPv6, tableNameExternal, "-m socket", "--transparent")
	if err != nil {
		return err
	}
	// bypass all socket
	err = t.setupIPTablesExcludeMatchers(isIPv6, tableNameExternal, "-m socket")
	if err != nil {
		return err
	}
	// tproxy lo marked
	err = t.setupIPTablesTProxyMatchers(isIPv6, tableNameExternal,
		"-i lo", "-m mark --mark", t.TProxyMark)
	if err != nil {
		return err
	}
	// bypass lo all
	err = t.setupIPTablesExcludeMatchers(isIPv6, tableNameExternal, "-i lo")
	if err != nil {
		return err
	}
	// bypass blacklist mac
	if len(t.ExcludeMAC) > 0 {
		if t.hasIPSet {
			// bypass blacklist mac by ipset
			err = t.setupIPTablesExcludeMatchers(isIPv6, tableNameExternal,
				"-m set --match-set", setNameExcludeMAC, "src")
			if err != nil {
				return err
			}
		} else {
			// bypass blacklist mac
			err = t.setupIPTablesExcludeCommands(isIPv6, tableNameExternal,
				newCommands("-m mac --mac-source", t.ExcludeMAC))
			if err != nil {
				return err
			}
		}
	}
	// bypass blacklist interface
	if len(t.ExcludeInterface) > 0 {
		if t.hasIPSet {
			// bypass blacklist interface by ipset
			err = t.setupIPTablesExcludeMatchers(isIPv6, tableNameExternal,
				"-m set --match-set", setNameExcludeInterface, "src,src")
			if err != nil {
				return err
			}
		} else {
			// bypass blacklist interface
			err = t.setupIPTablesExcludeCommands(isIPv6, tableNameExternal,
				newCommands("-i", t.ExcludeInterface))
			if err != nil {
				return err
			}
		}
	}
	// bypass unpsec/multicast/local address
	if t.hasAddrType {
		// bypass unpsec/multicast/local address by addrtype
		err = t.setupIPTablesExcludeCommands(isIPv6, tableNameExternal,
			newCommands("-m addrtype --dst-type", []string{"UNSPEC", "MULTICAST", "LOCAL"}))
		if err != nil {
			return err
		}
	} else if t.hasIPSet {
		// bypass unpsec/multicast/local address by ipset
		err = t.setupIPTablesExcludeMatchers(isIPv6, tableNameExternal,
			"-m set --match-set", setNameUnspec, "dst")
		if err != nil {
			return err
		}
		// bypass interface address by ipset
		err = t.setupIPTablesExcludeMatchers(isIPv6, tableNameExternal,
			"-m set --match-set", setNameLocal, "dst")
		if err != nil {
			return err
		}
	} else {
		// bypass unpsec/multicast/local address
		err = t.setupIPTablesExcludeCommands(isIPv6, tableNameExternal,
			newCommands("-d", unspecAddress))
		if err != nil {
			return err
		}
		// bypass interface address
		err = t.setupIPTablesExcludeCommands(isIPv6, tableNameExternal,
			newCommands("-d", interfaceAddress))
		if err != nil {
			return err
		}
	}
	// bypass blacklist address, except dns
	if t.hasIPSet {
		// bypass blacklist address by ipset, except dns
		if len(t.RouteExcludeAddress) > 0 || len(t.RouteExcludeAddressSet) > 0 {
			err = t.setupIPTablesExcludeExceptDNSMatchers(isIPv6, tableNameExternal,
				"-m set --match-set", setNameExcludeAddress, "dst")
			if err != nil {
				return err
			}
		}
	} else {
		// bypass blacklist address by ipset, except dns
		if len(t.RouteExcludeAddress) > 0 {
			err = t.setupIPTablesExcludeExceptDNSCommands(isIPv6, tableNameLocal,
				newCommands("-d", excludeAddress))
			if err != nil {
				return err
			}
		}
	}
	// tproxy mac/interface/address whitelist
	if t.hasIPSet {
		// bypass mac out of whitelist by ipset
		if len(t.IncludeMAC) > 0 {
			err = t.setupIPTablesExcludeMatchers(isIPv6, tableNameExternal,
				"-m set ! --match-set", setNameIncludeMAC, "src")
			if err != nil {
				return err
			}
		}
		// bypass interface out of whitelist by ipset
		if len(t.IncludeInterface) > 0 {
			err = t.setupIPTablesExcludeMatchers(isIPv6, tableNameExternal,
				"-m set ! --match-set", setNameIncludeInterface, "src,src")
			if err != nil {
				return err
			}
		}
		if len(t.RouteAddress) == 0 && len(t.RouteAddressSet) == 0 {
			// tproxy tcp && udp
			err = t.setupIPTablesTProxyAll(isIPv6, tableNameExternal)
			if err != nil {
				return err
			}
		} else {
			// tproxy tcp && udp dns
			err = t.setupIPTablesTProxyDNS(isIPv6, tableNameExternal)
			if err != nil {
				return err
			}
			// tproxy tcp && udp with address whitelist
			err = t.setupIPTablesTProxyMatchers(isIPv6, tableNameExternal,
				"-m set --match-set", setNameIncludeAddress, "dst")
			if err != nil {
				return err
			}
		}
	} else {
		commands := emptyCommands
		// set mac whitelist
		if len(t.IncludeMAC) > 0 {
			fillCommands(commands, "-m mac --mac-source", t.IncludeMAC)
		}
		// set interface whitelist
		if len(t.IncludeInterface) > 0 {
			var haslo bool
			var interfaces []string
			for _, inter := range t.IncludeInterface {
				if inter == "lo" {
					haslo = true
				} else {
					interfaces = append(interfaces, inter)
				}
			}
			commands = fillCommands(commands, "-i", interfaces)
			if haslo {
				commands = append(commands, []any{"-i", "lo"})
			}
		}
		if len(t.RouteAddress) == 0 {
			// tproxy tcp && udp matching mac whitelist && interface whitelist
			err = t.setupIPTablesTProxyCommands(isIPv6, tableNameExternal, commands)
			if err != nil {
				return err
			}
		} else {
			// tproxy tcp && udp dns matching mac whitelist && interface whitelist
			err := t.setupIPTablesTProxyDNSCommands(isIPv6, tableNameExternal, commands)
			if err != nil {
				return err
			}
			// tproxy tcp && udp matching mac whitelist && interface whitelist && address whitelest
			err = t.setupIPTablesTProxyCommands(isIPv6, tableNameExternal,
				fillCommands(commands, "-d", includeAddress))
			if err != nil {
				return err
			}
		}
	}
	err = t.setupIPTablesMatchers(isIPv6, "PREROUTING", "-j", tableNameExternal)
	if err != nil {
		return err
	}
	return nil
}

func (t *TProxy) iptablesInterfaceUpdate() {
	if t.enableIPv4 {
		t.iptablesInterfaceUpdateForFamily(false)
	}
	if t.enableIPv6 {
		t.iptablesInterfaceUpdateForFamily(true)
	}
}

func (t *TProxy) iptablesInterfaceUpdateForFamily(isIPv6 bool) {
	if t.hasIPSet {
		t.iptablesUpdateLocalAddressSetForFamily(isIPv6)
	} else {
		t.updateIPTablesLocalChain(isIPv6)
		t.updateIPTablesExternalChain(isIPv6)
	}
}

func (t *TProxy) updateIPTablesLocalChain(isIPv6 bool) error {
	var unspecAddress []string
	tableName := t.tableName + "-local"
	includeAddress := common.Filter(t.RouteAddress, func(it netip.Prefix) bool { return isIPv6 == it.Addr().Is6() })
	excludeAddress := common.Filter(t.RouteExcludeAddress, func(it netip.Prefix) bool { return isIPv6 == it.Addr().Is6() })
	interfaceAddress := common.Filter(t.interfaceAddress, func(it netip.Addr) bool { return it.Is6() == isIPv6 })
	if !isIPv6 {
		unspecAddress = []string{"0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32"}
	} else {
		unspecAddress = []string{"::/128", "::1/128", "fe80::/10"}
	}
	// flush table
	t.runIPTables(isIPv6, "-t mangle -F", tableName)
	// bypass self with uid && gid
	err := t.setupIPTablesExcludeMatchers(isIPv6, tableName,
		"-m owner --uid-owner", t.userId, "--gid-owner", t.groupId)
	if err != nil {
		return err
	}
	// bypass uid blacklist
	if len(t.ExcludeUID) > 0 {
		err = t.setupIPTablesExcludeCommands(isIPv6, tableName,
			newCommands("-m owner --uid-owner", t.ExcludeUID))
		if err != nil {
			return err
		}
	}
	// bypass gid blacklist
	if len(t.ExcludeGID) > 0 {
		err = t.setupIPTablesExcludeCommands(isIPv6, tableName,
			newCommands("-m owner --gid-owner", t.ExcludeGID))
		if err != nil {
			return err
		}
	}
	// bypass uidgid blacklist
	if len(t.ExcludeUIDGID) > 0 {
		err = t.setupIPTablesExcludeCommands(isIPv6, tableName,
			newCommands("-m owner", common.Map(t.ExcludeUIDGID, func(it option.UidGid) string {
				return fmt.Sprintf("--uid-owner %v --gid-owner %v", it.Uid, it.Gid)
			})))
		if err != nil {
			return err
		}
	}
	// bypass mark blacklist
	if len(t.ExcludeMark) > 0 {
		err = t.setupIPTablesExcludeCommands(isIPv6, tableName,
			newCommands("-m mark --mark", t.ExcludeMark))
		if err != nil {
			return err
		}
	}
	// bypass unpsec/multicast/local address
	err = t.setupIPTablesExcludeCommands(isIPv6, tableName,
		newCommands("-d", unspecAddress))
	if err != nil {
		return err
	}
	// bypass interface address
	err = t.setupIPTablesExcludeCommands(isIPv6, tableName,
		newCommands("-d", interfaceAddress))
	if err != nil {
		return err
	}
	// bypass address blacklist, except dns
	if len(t.RouteExcludeAddress) > 0 {
		// bypass address blacklist, except dns
		err = t.setupIPTablesExcludeExceptDNSCommands(isIPv6, tableName,
			newCommands("-d", excludeAddress))
		if err != nil {
			return err
		}
	}
	// set uid/gid/uidgid whitelist
	commands := emptyCommands
	if len(t.IncludeUID) > 0 || len(t.IncludeGID) > 0 || len(t.IncludeUIDGID) > 0 {
		var matchers []any
		// set uid whitelist
		if len(t.IncludeUID) > 0 {
			matchers = append(matchers, common.Map(t.IncludeUID, func(it option.IdRange) string {
				return fmt.Sprintf("--uid-owner %v", it)
			}))
		}
		// set gid whitelist
		if len(t.IncludeGID) > 0 {
			matchers = append(matchers, common.Map(t.IncludeGID, func(it option.IdRange) string {
				return fmt.Sprintf("--gid-owner %v", it)
			}))
		}
		// set uidgid whitelist
		if len(t.IncludeUIDGID) > 0 {
			matchers = append(matchers, common.Map(t.IncludeUIDGID, func(it option.UidGid) string {
				return fmt.Sprintf("--uid-owner %v --gid-owner %v", it.Uid, it.Gid)
			}))
		}
		commands = fillCommands(commands, "-m owner", matchers)
	}
	// mark all tcp && udp
	if len(t.RouteAddress) == 0 {
		err = t.setupIPTablesMarkCommands(isIPv6, tableName, commands)
		if err != nil {
			return err
		}
	} else {
		// mark all tcp && udp dns
		err = t.setupIPTablesMarkDNSCommands(isIPv6, tableName, commands)
		if err != nil {
			return err
		}
		// mark address whitelist
		err = t.setupIPTablesMarkCommands(isIPv6, tableName,
			fillCommands(commands, "-d", includeAddress))
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *TProxy) updateIPTablesExternalChain(isIPv6 bool) error {
	var unspecAddress []string
	tableName := t.tableName + "-external"
	includeAddress := common.Filter(t.RouteAddress, func(it netip.Prefix) bool { return isIPv6 == it.Addr().Is6() })
	excludeAddress := common.Filter(t.RouteExcludeAddress, func(it netip.Prefix) bool { return isIPv6 == it.Addr().Is6() })
	interfaceAddress := common.Filter(t.interfaceAddress, func(it netip.Addr) bool { return it.Is6() == isIPv6 })
	if !isIPv6 {
		unspecAddress = []string{"0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32"}
	} else {
		unspecAddress = []string{"::/128", "::1/128", "fe80::/10"}
	}
	// flush table
	t.runIPTables(isIPv6, "-t mangle -F", tableName)
	// mark already tproxy socket
	err := t.setupIPTablesMarkMatchers(isIPv6, tableName, "-m socket", "--transparent")
	if err != nil {
		return err
	}
	// bypass all socket
	err = t.setupIPTablesExcludeMatchers(isIPv6, tableName, "-m socket")
	if err != nil {
		return err
	}
	// bypass lo not marked
	err = t.setupIPTablesExcludeMatchers(isIPv6, tableName,
		"-i lo -m mark ! --mark", t.TProxyMark)
	if err != nil {
		return err
	}
	// bypass blacklist mac
	if len(t.ExcludeMAC) > 0 {
		err = t.setupIPTablesExcludeCommands(isIPv6, tableName,
			newCommands("-m mac --mac-source", t.ExcludeMAC))
		if err != nil {
			return err
		}
	}
	// bypass blacklist interface
	if len(t.ExcludeInterface) > 0 {
		err = t.setupIPTablesExcludeCommands(isIPv6, tableName,
			newCommands("-i", t.ExcludeInterface))
		if err != nil {
			return err
		}
	}
	// bypass unpsec/multicast/local address
	err = t.setupIPTablesExcludeCommands(isIPv6, tableName,
		newCommands("-d", unspecAddress))
	if err != nil {
		return err
	}
	// bypass interface address
	err = t.setupIPTablesExcludeCommands(isIPv6, tableName,
		newCommands("-d", interfaceAddress))
	if err != nil {
		return err
	}
	// bypass blacklist address by ipset, except dns
	if len(t.RouteExcludeAddress) > 0 {
		err = t.setupIPTablesExcludeExceptDNSCommands(isIPv6, tableName,
			newCommands("-d", excludeAddress))
		if err != nil {
			return err
		}
	}
	// tproxy mac/interface/address whitelist
	commands := emptyCommands
	// set mac whitelist
	if len(t.IncludeMAC) > 0 {
		commands = fillCommands(commands, "-m mac --mac-source", t.IncludeMAC)
	}
	// set interface whitelist
	if len(t.IncludeInterface) > 0 {
		commands = fillCommands(commands, "-i", t.IncludeInterface)
	}
	if len(t.RouteAddress) == 0 {
		// tproxy tcp && udp matching mac whitelist && interface whitelist
		err = t.setupIPTablesTProxyCommands(isIPv6, tableName, commands)
		if err != nil {
			return err
		}
	} else {
		// tproxy tcp && udp dns matching mac whitelist && interface whitelist
		err := t.setupIPTablesTProxyDNSCommands(isIPv6, tableName, commands)
		if err != nil {
			return err
		}
		// tproxy tcp && udp matching mac whitelist && interface whitelist && address whitelest
		err = t.setupIPTablesTProxyCommands(isIPv6, tableName,
			fillCommands(commands, "-d", includeAddress))
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *TProxy) cleanupIPTablesForFamily(isIPv6 bool) {
	tableNameLocal := t.tableName + "-local"
	tableNameExternal := t.tableName + "-external"
	// LOCAL
	t.runIPTables(isIPv6, "-t mangle -D OUTPUT -j", tableNameLocal)
	t.runIPTables(isIPv6, "-t mangle -F", tableNameLocal)
	t.runIPTables(isIPv6, "-t mangle -X", tableNameLocal)

	// EXTERNAL
	t.runIPTables(isIPv6, "-t mangle -D PREROUTING -j", tableNameExternal)
	t.runIPTables(isIPv6, "-t mangle -F", tableNameExternal)
	t.runIPTables(isIPv6, "-t mangle -X", tableNameExternal)
}
