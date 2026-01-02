//go:build !linux

package redirect

import (
	"context"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

type autoTProxyOptions struct{}

func newAutoTProxy(_ context.Context, _ adapter.Router, options *option.AutoTProxyOptions, _ []string, _ M.Socksaddr) (*autoTProxyOptions, error) {
	if options == nil || !options.Enabled {
		return nil, nil
	}
	return nil, os.ErrInvalid
}

func (t *TProxy) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	err := t.listener.Start()
	if err != nil {
		return err
	}
	return nil
}

func (t *TProxy) Close() error {
	return t.listener.Close()
}
