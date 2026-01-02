//go:build linux

package redirect

import "github.com/sagernet/sing/common"

var emptyCommands = [][]any{{}}

func (t *TProxy) setupIPTables() error {
	if t.hasIPSet {
		err := t.createIPSets()
		if err != nil {
			return err
		}
	}
	if t.enableIPv4 {
		err := t.setupIPTablesForFamily(false)
		if err != nil {
			return err
		}
	}
	if t.enableIPv6 {
		err := t.setupIPTablesForFamily(true)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *TProxy) setupIPTablesAcceptMatchers(isIPv6 bool, tableName string, matchers ...any) error {
	return t.setupIPTablesMarkCommandsWithMatchers(isIPv6, tableName, emptyCommands, matchers...)
}

func (t *TProxy) setupIPTablesAcceptCommandsWithMatchers(isIPv6 bool, tableName string, commands [][]any, matchers ...any) error {
	return t.setupIPTablesCommandsWithMatchers(
		isIPv6,
		tableName,
		fillCommands(commands, "-p", t.network),
		append(matchers, "-j ACCEPT")...,
	)
}

func (t *TProxy) setupIPTablesMarkAll(isIPv6 bool, tableName string) error {
	return t.setupIPTablesMarkCommands(isIPv6, tableName, emptyCommands)
}

func (t *TProxy) setupIPTablesMarkMatchers(isIPv6 bool, tableName string, matchers ...any) error {
	return t.setupIPTablesMarkCommandsWithMatchers(isIPv6, tableName, emptyCommands, matchers...)
}

func (t *TProxy) setupIPTablesMarkCommands(isIPv6 bool, tableName string, commands [][]any) error {
	return t.setupIPTablesMarkCommandsWithMatchers(isIPv6, tableName, commands)
}

func (t *TProxy) setupIPTablesMarkDNSCommands(isIPv6 bool, tableName string, commands [][]any) error {
	return t.setupIPTablesMarkCommandsWithMatchers(isIPv6, tableName, commands, "--dport", 53)
}

func (t *TProxy) setupIPTablesMarkCommandsWithMatchers(isIPv6 bool, tableName string, commands [][]any, matchers ...any) error {
	return t.setupIPTablesCommandsWithMatchers(
		isIPv6,
		tableName,
		fillCommands(commands, "-p", t.network),
		append(matchers, "-j MARK --set-mark", t.TProxyMark)...,
	)
}

func (t *TProxy) setupIPTablesTProxyDNS(isIPv6 bool, tableName string) error {
	return t.setupIPTablesTProxyDNSCommands(isIPv6, tableName, emptyCommands)
}

func (t *TProxy) setupIPTablesTProxyDNSCommands(isIPv6 bool, tableName string, commands [][]any) error {
	return t.setupIPTablesTProxyCommandsWithMatchers(isIPv6, tableName, commands, "--dport", 53)
}

func (t *TProxy) setupIPTablesTProxyAll(isIPv6 bool, tableName string) error {
	return t.setupIPTablesTProxyCommands(isIPv6, tableName, emptyCommands)
}

func (t *TProxy) setupIPTablesTProxyMatchers(isIPv6 bool, tableName string, matchers ...any) error {
	return t.setupIPTablesTProxyCommandsWithMatchers(isIPv6, tableName, emptyCommands, matchers...)
}

func (t *TProxy) setupIPTablesTProxyCommands(isIPv6 bool, tableName string, commands [][]any) error {
	return t.setupIPTablesTProxyCommandsWithMatchers(isIPv6, tableName, commands)
}

func (t *TProxy) setupIPTablesTProxyCommandsWithMatchers(isIPv6 bool, tableName string, commands [][]any, matchers ...any) error {
	matchers = append(matchers, "-j TPROXY")
	if !t.listen.Addr.IsUnspecified() {
		matchers = append(matchers, "--on-ip", t.listen.Addr)
	}
	matchers = append(matchers, "--on-port", t.listen.Port, "--tproxy-mark", t.TProxyMark)
	return t.setupIPTablesCommandsWithMatchers(
		isIPv6,
		tableName,
		fillCommands(commands, "-p", t.network),
		matchers...,
	)
}

func (t *TProxy) setupIPTablesExcludeAddressExceptDNS(isIPv6 bool, tableName string, addresses []any) error {
	return t.setupIPTablesExcludeExceptDNSCommands(isIPv6, tableName,
		newCommands("-d", addresses))
}

func (t *TProxy) setupIPTablesExcludeCommands(isIPv6 bool, tableName string, commands [][]any) error {
	return t.setupIPTablesExcludeCommandsWithMatchers(isIPv6, tableName, commands)
}

func (t *TProxy) setupIPTablesExcludeMatchers(isIPv6 bool, tableName string, matchers ...any) error {
	return t.setupIPTablesExcludeCommandsWithMatchers(isIPv6, tableName, emptyCommands, matchers...)
}

func (t *TProxy) setupIPTablesExcludeExceptDNSCommands(isIPv6 bool, tableName string, commands [][]any) error {
	return t.setupIPTablesExcludeCommandsWithMatchers(isIPv6, tableName,
		fillCommands(commands, "-p", t.network),
		"! --dport", 53)
}

func (t *TProxy) setupIPTablesExcludeExceptDNSMatchers(isIPv6 bool, tableName string, matchers ...any) error {
	return t.setupIPTablesExcludeCommandsWithMatchers(isIPv6, tableName,
		newCommands("-p", t.network),
		append([]any{"! --dport", 53}, matchers...)...)
}

func (t *TProxy) setupIPTablesExcludeCommandsWithMatchers(isIPv6 bool, tableName string, commands [][]any, matchers ...any) error {
	return t.setupIPTablesCommandsWithMatchers(
		isIPv6,
		tableName,
		commands,
		append(matchers, "-j RETURN")...,
	)
}

func (t *TProxy) setupIPTablesMatchers(isIPv6 bool, tableName string, matchers ...any) error {
	return t.setupIPTablesCommandsWithMatchers(isIPv6, tableName, emptyCommands, matchers...)
}

func (t *TProxy) setupIPTablesCommandsWithMatchers(isIPv6 bool, tableName string, commands [][]any, matchers ...any) error {
	for _, command := range commands {
		err := t.runIPTables(
			isIPv6,
			append(
				append(
					[]any{"-t mangle -A", tableName},
					command...),
				matchers...)...)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *TProxy) createIPTablesTable(isIPv6 bool, tableName string) error {
	return t.runIPTables(isIPv6, "-t mangle -N", tableName)
}

func (t *TProxy) cleanupIPTables() {
	if t.hasIPSet {
		t.cleanupIPSets()
	}
	if t.enableIPv4 {
		t.cleanupIPTablesForFamily(false)
	}
	if t.enableIPv6 {
		t.cleanupIPTablesForFamily(true)
	}
}

func mapToAny[T any](arr []T) []any {
	return common.Map(arr, func(it T) any { return it })
}

func newCommands[T any](flag string, matchers []T) [][]any {
	return fillCommands(emptyCommands, flag, matchers)
}

func fillCommands[T any](commands [][]any, flag string, matchers []T) [][]any {
	var newCommands [][]any
	for _, command := range commands {
		for _, matcher := range matchers {
			newCommands = append(newCommands, append(command, flag, matcher))
		}
	}
	return newCommands
}
