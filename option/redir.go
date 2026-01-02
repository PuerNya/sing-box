package option

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

type RedirectInboundOptions struct {
	ListenOptions
}

type TProxyInboundOptions struct {
	ListenOptions
	Network    NetworkList        `json:"network,omitempty"`
	AutoTProxy *AutoTProxyOptions `json:"auto_tproxy,omitempty"`
}

type AutoTProxyOptions struct {
	Enabled                bool                             `json:"enabled,omitempty"`
	RouteAddress           badoption.Listable[netip.Prefix] `json:"route_address,omitempty"`
	RouteAddressSet        badoption.Listable[string]       `json:"route_address_set,omitempty"`
	RouteExcludeAddress    badoption.Listable[netip.Prefix] `json:"route_exclude_address,omitempty"`
	RouteExcludeAddressSet badoption.Listable[string]       `json:"route_exclude_address_set,omitempty"`
	IncludeInterface       badoption.Listable[string]       `json:"include_interface,omitempty"`
	ExcludeInterface       badoption.Listable[string]       `json:"exclude_interface,omitempty"`
	IncludeUID             badoption.Listable[IdRange]      `json:"include_uid,omitempty"`
	IncludeGID             badoption.Listable[IdRange]      `json:"include_gid,omitempty"`
	IncludeUIDGID          badoption.Listable[UidGid]       `json:"include_uid_gid,omitempty"`
	ExcludeUID             badoption.Listable[IdRange]      `json:"exclude_uid,omitempty"`
	ExcludeGID             badoption.Listable[IdRange]      `json:"exclude_gid,omitempty"`
	ExcludeUIDGID          badoption.Listable[UidGid]       `json:"exclude_uid_gid,omitempty"`
	ExcludeMark            badoption.Listable[uint32]       `json:"exclude_mark,omitempty"`
	IncludeMAC             badoption.Listable[HardwareAddr] `json:"include_mac,omitempty"`
	ExcludeMAC             badoption.Listable[HardwareAddr] `json:"exclude_mac,omitempty"`
	TProxyMark             uint32                           `json:"tproxy_mark,omitempty"`
	TProxyTableId          int                              `json:"tproxy_table_id,omitempty"`

	// todo
	// IncludePackage         badoption.Listable[string]       `json:"include_package,omitempty"`
	// ExcludePackage         badoption.Listable[string]       `json:"exclude_package,omitempty"`
}

type HardwareAddr net.HardwareAddr

func (a *HardwareAddr) String() string {
	return (*net.HardwareAddr)(a).String()
}

func (a HardwareAddr) MarshalJSON() ([]byte, error) {
	return []byte(a.String()), nil
}

func (o *HardwareAddr) UnmarshalJSON(bytes []byte) error {
	var value string
	err := json.Unmarshal(bytes, &value)
	if err != nil {
		return err
	}
	hw, err := net.ParseMAC(value)
	if err != nil {
		return err
	}
	*o = HardwareAddr(hw)
	return nil
}

type IdRange struct {
	start uint32
	end   uint32
}

func (i *IdRange) String() string {
	if i.start == i.end {
		return fmt.Sprintf("%d", i.start)
	}
	return fmt.Sprintf("%d-%d", i.start, i.end)
}

func (i IdRange) MarshalJSON() ([]byte, error) {
	if i.start == i.end {
		return json.Marshal(i.start)
	}
	return json.Marshal(i.String())
}

func (t *IdRange) UnmarshalJSON(bytes []byte) error {
	var valueNumber uint32
	err := json.Unmarshal(bytes, &valueNumber)
	if err == nil {
		*t = IdRange{valueNumber, valueNumber}
		return nil
	}
	var valueString string
	err = json.Unmarshal(bytes, &valueString)
	if err != nil {
		return err
	}
	formatErr := E.New("invalid id range format")
	if !strings.Contains(valueString, "-") {
		return E.Cause(formatErr, "missing '-'")
	}
	arr := strings.SplitN(valueString, "-", 2)
	start, err := strconv.Atoi(arr[0])
	if err != nil {
		return E.Cause(formatErr, E.Cause(err, "parse id start"))
	}
	if start < 0 {
		return E.Cause(formatErr, E.Cause(E.New("negative number"), "parse id start"))
	}
	end, err := strconv.Atoi(arr[1])
	if err != nil {
		return E.Cause(formatErr, E.Cause(err, "parse id end"))
	}
	if end < 0 {
		return E.Cause(formatErr, E.Cause(E.New("negative number"), "parse id end"))
	}
	if start > end {
		return E.Cause(formatErr, E.New("start id must be smaller than end id"))
	}
	*t = IdRange{uint32(start), uint32(end)}
	return nil
}

type UidGid struct {
	Uid IdRange
	Gid IdRange
}

func (i UidGid) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%v:%v", i.Uid, i.Gid))
}

func (i *UidGid) UnmarshalJSON(bytes []byte) error {
	var valueString string
	err := json.Unmarshal(bytes, &valueString)
	if err != nil {
		return err
	}
	if !strings.Contains(valueString, ":") {
		return E.Cause(E.New("invalid uid_gid format"), "missing ':'")
	}
	arr := strings.SplitN(valueString, ":", 2)
	var valueUid IdRange
	err = json.Unmarshal([]byte(arr[0]), &valueUid)
	if err != nil {
		return E.Cause(E.New("invalid uid_gid format"), E.Cause(err, "parse uid"))
	}
	var valueGid IdRange
	err = json.Unmarshal([]byte(arr[1]), &valueGid)
	if err != nil {
		return E.Cause(E.New("invalid uid_gid format"), E.Cause(err, "parse gid"))
	}
	*i = UidGid{valueUid, valueGid}
	return nil
}
