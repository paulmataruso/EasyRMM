package auditfwd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Transports.
const (
	UDP = "udp"
	TCP = "tcp"
	TLS = "tls"
)

const (
	dialTimeout  = 10 * time.Second
	writeTimeout = 15 * time.Second
	// acceptWait is how long a new stream connection is watched for the
	// collector turning it away before anything is sent. With TLS 1.3 a
	// collector refuses a client certificate only after the client's side
	// of the handshake has finished.
	acceptWait = 500 * time.Millisecond
)

// errClosed is a collector closing a connection it has just accepted.
var errClosed = errors.New("the collector closed the connection as soon as it was opened")

// Destination is a collector and how to reach it.
type Destination struct {
	Transport  string
	Host       string
	Port       int
	CACert     string // PEM; empty trusts the system's certificate authorities
	ClientCert string // PEM; for collectors that require a client certificate
	ClientKey  []byte // PEM
}

// Address is host:port.
func (d Destination) Address() string { return net.JoinHostPort(d.Host, strconv.Itoa(d.Port)) }

func (d Destination) tlsConfig() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: d.Host}
	if d.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(d.CACert)) {
			return nil, errors.New("the CA certificate is not a PEM certificate")
		}
		cfg.RootCAs = pool
	}
	if d.ClientCert != "" {
		pair, err := tls.X509KeyPair([]byte(d.ClientCert), d.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("the client certificate and key do not form a pair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}

// conn is an open connection to a collector.
type conn struct {
	nc    net.Conn
	udp   bool
	limit int
}

func dial(ctx context.Context, d Destination) (*conn, error) {
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	switch d.Transport {
	case UDP:
		nc, err := dialer.DialContext(ctx, "udp", d.Address())
		if err != nil {
			return nil, err
		}
		return &conn{nc: nc, udp: true, limit: maxDatagram}, nil
	case TCP:
		nc, err := dialer.DialContext(ctx, "tcp", d.Address())
		if err != nil {
			return nil, err
		}
		return accepted(&conn{nc: nc, limit: maxFrame})
	case TLS:
		cfg, err := d.tlsConfig()
		if err != nil {
			return nil, err
		}
		td := &tls.Dialer{NetDialer: dialer, Config: cfg}
		nc, err := td.DialContext(ctx, "tcp", d.Address())
		if err != nil {
			return nil, err
		}
		return accepted(&conn{nc: nc, limit: maxFrame})
	}
	return nil, fmt.Errorf("unknown transport %q", d.Transport)
}

// accepted waits briefly for the collector to turn a new connection away.
func accepted(c *conn) (*conn, error) {
	_ = c.nc.SetReadDeadline(time.Now().Add(acceptWait))
	var b [64]byte
	_, err := c.nc.Read(b[:])
	_ = c.nc.SetReadDeadline(time.Time{})
	var ne net.Error
	switch {
	case err == nil, errors.As(err, &ne) && ne.Timeout():
		return c, nil
	case errors.Is(err, io.EOF):
		err = errClosed
	}
	c.close()
	return nil, err
}

// alive reports whether a stream connection is still open. Collectors never
// send on a syslog stream, so a read that finds nothing within a
// millisecond means the connection is idle, and one that finds the end of
// the stream means the collector closed it.
func (c *conn) alive() bool {
	if c.udp {
		return true
	}
	_ = c.nc.SetReadDeadline(time.Now().Add(time.Millisecond))
	var b [64]byte
	_, err := c.nc.Read(b[:])
	_ = c.nc.SetReadDeadline(time.Time{})
	var ne net.Error
	return err == nil || errors.As(err, &ne) && ne.Timeout()
}

// send writes messages: one datagram each over UDP, octet-counted frames in
// one write over TCP and TLS.
func (c *conn) send(msgs [][]byte) error {
	_ = c.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	if c.udp {
		for _, m := range msgs {
			if _, err := c.nc.Write(m); err != nil {
				return err
			}
		}
		return nil
	}
	size := 0
	for _, m := range msgs {
		size += len(m) + 8
	}
	buf := make([]byte, 0, size)
	for _, m := range msgs {
		buf = append(buf, frame(m)...)
	}
	_, err := c.nc.Write(buf)
	return err
}

// refused reports, after a datagram, whether the collector's host answered
// that nothing listens on the port. Silence proves nothing: UDP has no
// acknowledgement.
func (c *conn) refused(wait time.Duration) bool {
	if !c.udp {
		return false
	}
	_ = c.nc.SetReadDeadline(time.Now().Add(wait))
	var b [1]byte
	_, err := c.nc.Read(b[:])
	_ = c.nc.SetReadDeadline(time.Time{})
	return errors.Is(err, syscall.ECONNREFUSED)
}

func (c *conn) close() { _ = c.nc.Close() }

// describe turns a connection error into a sentence for the console.
func describe(d Destination, err error) string {
	var dnsErr *net.DNSError
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verify *tls.CertificateVerificationError
	var ne net.Error
	var msg string
	switch {
	case errors.As(err, &dnsErr):
		msg = fmt.Sprintf("The name %s could not be resolved.", d.Host)
	case errors.Is(err, syscall.ECONNREFUSED):
		msg = fmt.Sprintf("Connection refused: nothing accepts %s connections on %s.", transportName(d.Transport), d.Address())
	case errors.As(err, &unknownCA):
		msg = "The collector's certificate is not signed by a trusted certificate authority. Add the authority's certificate."
	case errors.As(err, &hostErr):
		msg = fmt.Sprintf("The collector's certificate is not valid for %s.", d.Host)
	case errors.As(err, &invalid):
		msg = "The collector's certificate is not valid: " + invalid.Error() + "."
	case errors.As(err, &verify):
		msg = "The collector's certificate could not be verified: " + verify.Err.Error() + "."
	case errors.As(err, &ne) && ne.Timeout():
		msg = fmt.Sprintf("Timed out reaching %s.", d.Address())
	case errors.Is(err, errClosed) && d.Transport == TLS:
		msg = "The collector closed the connection as soon as it was opened. It may require a client certificate, or not accept this one."
	case strings.Contains(err.Error(), "remote error: tls: "):
		msg = "The collector refused the TLS connection (" + strings.TrimPrefix(err.Error()[strings.Index(err.Error(), "remote error: tls: "):], "remote error: tls: ") + "). It may require a client certificate, or not accept this one."
	case errors.Is(err, errClosed):
		msg = "The collector closed the connection as soon as it was opened. Check that it accepts connections from this server."
	default:
		msg = err.Error()
	}
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return msg
}

func transportName(t string) string {
	switch t {
	case UDP:
		return "UDP"
	case TLS:
		return "TLS"
	}
	return "TCP"
}
