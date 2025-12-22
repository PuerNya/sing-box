package http

import (
	"context"
	"net"
	"net/http"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

var ConfigureHTTP3Dialer func(dialer N.Dialer, serverAddress M.Socksaddr, tlsConfig tls.Config, factor RequsetFactor) (N.Dialer, error)

type RequsetFactor interface {
	NewRequest(destination M.Socksaddr) (*http.Request, error)
}

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.HTTPOutboundOptions](registry, C.TypeHTTP, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger    logger.ContextLogger
	dialer    N.Dialer
	server    M.Socksaddr
	username  string
	password  string
	host      string
	path      string
	headers   http.Header
	tlsConfig tls.Config
	h2        *client
	h3Dialer  N.Dialer
	uotClient *uot.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HTTPOutboundOptions) (adapter.Outbound, error) {
	if options.UseH3 {
		if options.TLS == nil || !options.TLS.Enabled {
			return nil, C.ErrTLSRequired
		}
		options.UDPFragmentDefault = true
	}
	detour, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeHTTP, tag, []string{N.NetworkTCP}, options.DialerOptions),
		logger:    logger,
		dialer:    detour,
		server:    options.ServerOptions.Build(),
		username:  options.Username,
		password:  options.Password,
		path:      options.Path,
		headers:   options.Headers.Build(),
		tlsConfig: tlsConfig,
	}
	if outbound.headers != nil {
		outbound.host = outbound.headers.Get("Host")
		outbound.headers.Del("Host")
	}
	if options.UseH3 {
		h3Dialer, err := ConfigureHTTP3Dialer(outbound.dialer, outbound.server, outbound.tlsConfig, (*httpDialer)(outbound))
		if err != nil {
			return nil, err
		} else {
			outbound.h3Dialer = h3Dialer
		}
	} else if tlsConfig != nil {
		outbound.h2 = &client{}
	}
	if uotOptions := common.PtrValueOrDefault(options.UDPOverTCP); uotOptions.Enabled {
		outbound.uotClient = &uot.Client{
			Dialer:  (*httpDialer)(outbound),
			Version: uotOptions.Version,
		}
	}
	return outbound, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		if h.uotClient != nil {
			h.logger.InfoContext(ctx, "outbound UoT connect packet connection to ", destination)
			return h.uotClient.DialContext(ctx, network, destination)
		}
	}
	return (*httpDialer)(h).DialContext(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.uotClient != nil {
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return h.uotClient.ListenPacket(ctx, destination)
	}
	return (*httpDialer)(h).ListenPacket(ctx, destination)
}

var _ N.Dialer = (*httpDialer)(nil)

type httpDialer Outbound

func (h *httpDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		if h.tlsConfig == nil {
			return h.dialHTTP1(ctx, network, destination)
		}
		if h.h3Dialer != nil {
			return h.h3Dialer.DialContext(ctx, network, destination)
		}
		return h.dialH2(ctx, network, destination)
	case N.NetworkUDP:
		if h.h3Dialer != nil {
			h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
			return h.h3Dialer.DialContext(ctx, network, destination)
		}
		return nil, os.ErrInvalid
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *httpDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.h3Dialer == nil {
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return h.h3Dialer.ListenPacket(ctx, destination)
	}
	return nil, os.ErrInvalid
}
