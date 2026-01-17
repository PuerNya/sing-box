package constant

const (
	V2RayTransportTypeHTTP        = "http"
	V2RayTransportTypeWebsocket   = "ws"
	V2RayTransportTypeQUIC        = "quic"
	V2RayTransportTypeGRPC        = "grpc"
	V2RayTransportTypeHTTPUpgrade = "httpupgrade"
	V2RayTransportTypeXHTTP       = "xhttp"
)

const XHTTPDefaultMaxEachPostBytes = 1000000

const (
	XHTTPUploadModeStreamUp  = "stream-up"
	XHTTPUploadModePacketUp  = "packet-up"
	XHTTPUploadModeStreamOne = "stream-one"
)
