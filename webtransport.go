package webtransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/langhuihui/webtransport-go/h3"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/quicvarint"
	"github.com/marten-seemann/qpack"
)

const (
	// https://tools.ietf.org/html/draft-vvv-webtransport-quic-02#section-3.1
	alpnQuicTransport = "wq-vvv-01"

	// https://tools.ietf.org/html/draft-vvv-webtransport-quic-02#section-3.2
	maxClientIndicationLength = 65535
)

type clientIndicationKey int16

const (
	clientIndicationKeyOrigin clientIndicationKey = 0
	clientIndicationKeyPath                       = 1
)

// ClientIndication, see https://tools.ietf.org/html/draft-vvv-webtransport-quic-02#section-3.2
type ClientIndication struct {
	// Origin indication value.
	Origin string
	// Path indication value.
	Path string
}

// Config for WebTransportServerQuic.
type Config struct {
	http.Handler
	// ListenAddr sets an address to bind server to.
	ListenAddr string
	// TLSCertPath defines a path to .crt cert file.
	TLSCertPath string
	// TLSKeyPath defines a path to .key cert file
	TLSKeyPath string
	// AllowedOrigins represents list of allowed origins to connect from.
	AllowedOrigins []string
}

// WebTransportServer can handle WebTransport QUIC connections.
// This example only shows bidirectional streams in action. Unidirectional
// stream communication is also possible but not implemented here. For unreliable
// communication with UDP datagram mentioned in
// https://tools.ietf.org/html/draft-vvv-webtransport-quic-02#section-5
// quic-go should implement https://tools.ietf.org/html/draft-ietf-quic-datagram-00
// draft (there is an ongoing pull request – see https://github.com/lucas-clemente/quic-go/pull/2162).
type WebTransportServer struct {
	Config
	Session chan quic.Session
}

func NewWebTransportServer(config Config) *WebTransportServer {
	if config.Handler == nil {
		config.Handler = http.DefaultServeMux
	}
	return &WebTransportServer{
		Config:  config,
		Session: make(chan quic.Session),
	}
}

// Run server.
func (s *WebTransportServer) Run() error {
	// server := http3.Server{
	// 	Server:             &http.Server{Addr: ":8080"},
	// 	QuicConfig:         &quic.Config{
	// 		EnableDatagrams: true,
	// 	},
	// 	EnableDatagrams:    true,
	// 	EnableWebTransport: true,
	// }
	// return server.ListenAndServeTLS(s.config.TLSCertPath, s.config.TLSKeyPath)

	// return http3.ListenAndServeQUIC(s.config.ListenAddr, s.config.TLSCertPath, s.config.TLSKeyPath, sm)
	listener, err := quic.ListenAddr(s.ListenAddr, s.generateTLSConfig(), &quic.Config{
		EnableDatagrams: true,
	})
	if err != nil {
		return err
	}
	log.Printf("WebTransport Server listening on: %s", s.ListenAddr)
	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		log.Printf("session accepted: %s", sess.RemoteAddr().String())
		go s.handleSession(sess)
	}
}

// https://datatracker.ietf.org/doc/html/draft-ietf-masque-h3-datagram-05#section-9.1
const H3_DATAGRAM_05 = 0xffd277

// https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-h3-websockets-00#section-5
const ENABLE_CONNECT_PROTOCOL = 0x08

// https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-01.html#section-7.2
const ENABLE_WEBTRNASPORT = 0x2b603742

func (s *WebTransportServer) handleSession(sess quic.Session) {
	str, err := sess.OpenUniStream()
	if err != nil {
		return
	}
	// 发送Setting帧
	buf := &bytes.Buffer{}
	quicvarint.Write(buf, 0) // stream type
	(&h3.SettingsFrame{Datagram: true, Other: map[uint64]uint64{uint64(H3_DATAGRAM_05): uint64(1), uint64(ENABLE_CONNECT_PROTOCOL): uint64(1), uint64(ENABLE_WEBTRNASPORT): uint64(1)}}).Write(buf)
	str.Write(buf.Bytes())

	stream, err := sess.AcceptUniStream(context.Background())
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("read settings from control stream id: %d", stream.StreamID())
	// TODO: 读取Setting帧

	// indication, err := receiveClientIndication(stream)
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	// log.Printf("client indication: %+v", indication)
	// if err := s.validateClientIndication(indication); err != nil {
	// 	log.Println(err)
	// 	return
	// }
	requestStream, err := sess.AcceptStream(context.Background())
	if err != nil {
		log.Printf("request stream err: %v", err)
		return
	}
	log.Printf("request stream accepted: %d", stream.StreamID())
	
	ctx := requestStream.Context()
	ctx = context.WithValue(ctx, http3.ServerContextKey, s)
	ctx = context.WithValue(ctx, http.LocalAddrContextKey, sess.LocalAddr())
	frame, err := h3.ParseNextFrame(requestStream)
	if err != nil {
		log.Printf("request stream ParseNextFrame err: %v", err)
		return
	}
	hf, ok := frame.(*h3.HeadersFrame)
	if !ok {
		log.Println("request stream got not HeadersFrame")
		return
	}
	headerBlock := make([]byte, hf.Length)
	if _, err := io.ReadFull(requestStream, headerBlock); err != nil {
		log.Printf("request stream read headerBlock err: %v", err)
	}
	decoder := qpack.NewDecoder(nil)
	hfs, err := decoder.DecodeFull(headerBlock)
	if err != nil {
		log.Printf("request stream decoder err: %v", err)
		return
	}
	req, err := h3.RequestFromHeaders(hfs)
	if err != nil {
		log.Printf("request stream RequestFromHeaders err: %v", err)
		return
	}
	req.RemoteAddr = sess.RemoteAddr().String()
	req = req.WithContext(ctx)
	r := h3.NewResponseWriter(requestStream)
	r.Header().Add("sec-webtransport-http3-draft", "draft02")
	s.ServeHTTP(r, req)
	r.WriteHeader(200)
	r.Flush()
	// requestStream.CancelRead(quic.StreamErrorCode(0x100))
	//requestStream.Close()
	s.Session <- sess
}

func (s *WebTransportServer) communicate(sess quic.Session) error {
	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			return err
		}
		log.Printf("bidirectional stream accepted: %d", stream.StreamID())
		// if _, err := io.Copy(loggingWriter{stream}, loggingReader{stream}); err != nil {
		// 	return err
		// }
		// log.Printf("bidirectional stream closed: %d", stream.StreamID())
	}
}

// The client indication is a sequence of key-value pairs that are
// formatted in the following way:
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Key (16)            |          Length (16)          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Value (*)                         ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func receiveClientIndication(stream quic.ReceiveStream) (ClientIndication, error) {
	var clientIndication ClientIndication
	reader := io.LimitReader(stream, maxClientIndicationLength)

	done := false

	for {
		if done {
			break
		}

		var key int16
		err := binary.Read(reader, binary.BigEndian, &key)
		if err != nil {
			if err == io.EOF {
				done = true
			} else {
				return clientIndication, err
			}
		}

		var valueLength int16
		err = binary.Read(reader, binary.BigEndian, &valueLength)
		if err != nil {
			return clientIndication, err
		}

		buf := make([]byte, valueLength)
		n, err := reader.Read(buf)
		if err != nil {
			if err == io.EOF {
				done = true
			} else {
				return clientIndication, err
			}
		}
		if int16(n) != valueLength {
			return clientIndication, errors.New("read less than expected")
		}
		value := string(buf)

		switch clientIndicationKey(key) {
		case clientIndicationKeyOrigin:
			clientIndication.Origin = value
		case clientIndicationKeyPath:
			clientIndication.Path = value
		default:
			log.Printf("skip unknown client indication key: %d: %s", key, value)
		}
	}
	return clientIndication, nil
}

func (s *WebTransportServer) generateTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(s.TLSCertPath, s.TLSKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3", "h3-32", "h3-31", "h3-30", "h3-29"},
	}
}

var errBadOrigin = errors.New("bad origin")

func (s *WebTransportServer) validateClientIndication(indication ClientIndication) error {
	u, err := url.Parse(indication.Origin)
	if err != nil {
		return errBadOrigin
	}
	if !stringInSlice(u.Host, s.AllowedOrigins) {
		return errBadOrigin
	}
	return nil
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	log.Printf("---> %s", string(b))
	return w.Writer.Write(b)
}

// A wrapper for io.Reader that also logs the message.
type loggingReader struct{ io.Reader }

func (r loggingReader) Read(buf []byte) (n int, err error) {
	n, err = r.Reader.Read(buf)
	if n > 0 {
		log.Printf("<--- %s", string(buf[:n]))
	}
	return
}
