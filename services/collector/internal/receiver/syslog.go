// Package receiver provides log reception from various sources.
package receiver

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SyslogMessage represents a parsed syslog message.
type SyslogMessage struct {
	Timestamp    time.Time
	Hostname     string
	AppName      string
	ProcID       string
	MsgID        string
	Facility     int
	Severity     int
	Priority     int
	Version      int
	Message      string
	StructData   map[string]map[string]string
	RawMessage   string
	ReceivedAt   time.Time
	SourceIP     string
	SourcePort   int
	Protocol     string
	RFC          string // "3164" or "5424"
}

// SyslogConfig holds syslog receiver configuration.
type SyslogConfig struct {
	UDPAddr     string
	TCPAddr     string
	TLSAddr     string
	TLSCertPath string
	TLSKeyPath  string
	MaxMsgSize  int
	ParseRFC    bool
}

// SyslogReceiver receives syslog messages over UDP, TCP, and TLS.
type SyslogReceiver struct {
	config     SyslogConfig
	output     chan<- *SyslogMessage
	udpConn    *net.UDPConn
	tcpLn      net.Listener
	tlsLn      net.Listener
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	logger     *slog.Logger

	// Metrics
	messagesReceived atomic.Uint64
	bytesReceived    atomic.Uint64
	parseErrors      atomic.Uint64
}

// NewSyslogReceiver creates a new syslog receiver.
func NewSyslogReceiver(cfg SyslogConfig, output chan<- *SyslogMessage, logger *slog.Logger) *SyslogReceiver {
	ctx, cancel := context.WithCancel(context.Background())
	return &SyslogReceiver{
		config: cfg,
		output: output,
		ctx:    ctx,
		cancel: cancel,
		logger: logger.With("component", "syslog-receiver"),
	}
}

// Start begins receiving syslog messages.
func (r *SyslogReceiver) Start() error {
	// Start UDP listener
	if r.config.UDPAddr != "" {
		if err := r.startUDP(); err != nil {
			return fmt.Errorf("failed to start UDP listener: %w", err)
		}
	}

	// Start TCP listener
	if r.config.TCPAddr != "" {
		if err := r.startTCP(); err != nil {
			return fmt.Errorf("failed to start TCP listener: %w", err)
		}
	}

	// Start TLS listener
	if r.config.TLSAddr != "" && r.config.TLSCertPath != "" {
		if err := r.startTLS(); err != nil {
			return fmt.Errorf("failed to start TLS listener: %w", err)
		}
	}

	return nil
}

// Stop stops the syslog receiver.
func (r *SyslogReceiver) Stop() error {
	r.cancel()

	if r.udpConn != nil {
		r.udpConn.Close()
	}
	if r.tcpLn != nil {
		r.tcpLn.Close()
	}
	if r.tlsLn != nil {
		r.tlsLn.Close()
	}

	r.wg.Wait()
	return nil
}

// Stats returns receiver statistics.
func (r *SyslogReceiver) Stats() map[string]uint64 {
	return map[string]uint64{
		"messages_received": r.messagesReceived.Load(),
		"bytes_received":    r.bytesReceived.Load(),
		"parse_errors":      r.parseErrors.Load(),
	}
}

func (r *SyslogReceiver) startUDP() error {
	addr, err := net.ResolveUDPAddr("udp", r.config.UDPAddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	r.udpConn = conn

	// Set buffer size for high throughput
	conn.SetReadBuffer(16 * 1024 * 1024) // 16MB

	r.logger.Info("UDP syslog listener started", "addr", r.config.UDPAddr)

	r.wg.Add(1)
	go r.handleUDP()

	return nil
}

func (r *SyslogReceiver) handleUDP() {
	defer r.wg.Done()

	buf := make([]byte, r.config.MaxMsgSize)
	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		r.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := r.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if r.ctx.Err() == nil {
				r.logger.Error("UDP read error", "error", err)
			}
			continue
		}

		r.bytesReceived.Add(uint64(n))

		msg := r.parseMessage(string(buf[:n]), remoteAddr.IP.String(), remoteAddr.Port, "udp")
		if msg != nil {
			select {
			case r.output <- msg:
				r.messagesReceived.Add(1)
			default:
				// Channel full - apply backpressure
				r.logger.Warn("output channel full, dropping message")
			}
		}
	}
}

func (r *SyslogReceiver) startTCP() error {
	ln, err := net.Listen("tcp", r.config.TCPAddr)
	if err != nil {
		return err
	}
	r.tcpLn = ln

	r.logger.Info("TCP syslog listener started", "addr", r.config.TCPAddr)

	r.wg.Add(1)
	go r.acceptTCP(ln, "tcp")

	return nil
}

func (r *SyslogReceiver) startTLS() error {
	cert, err := tls.LoadX509KeyPair(r.config.TLSCertPath, r.config.TLSKeyPath)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", r.config.TLSAddr, tlsConfig)
	if err != nil {
		return err
	}
	r.tlsLn = ln

	r.logger.Info("TLS syslog listener started", "addr", r.config.TLSAddr)

	r.wg.Add(1)
	go r.acceptTCP(ln, "tls")

	return nil
}

func (r *SyslogReceiver) acceptTCP(ln net.Listener, protocol string) {
	defer r.wg.Done()

	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			if r.ctx.Err() == nil {
				r.logger.Error("accept error", "protocol", protocol, "error", err)
			}
			continue
		}

		r.wg.Add(1)
		go r.handleTCPConn(conn, protocol)
	}
}

func (r *SyslogReceiver) handleTCPConn(conn net.Conn, protocol string) {
	defer r.wg.Done()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, r.config.MaxMsgSize), r.config.MaxMsgSize)

	for scanner.Scan() {
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		line := scanner.Text()
		r.bytesReceived.Add(uint64(len(line)))

		msg := r.parseMessage(line, remoteAddr.IP.String(), remoteAddr.Port, protocol)
		if msg != nil {
			select {
			case r.output <- msg:
				r.messagesReceived.Add(1)
			default:
				r.logger.Warn("output channel full, dropping message")
			}
		}
	}

	if err := scanner.Err(); err != nil && r.ctx.Err() == nil {
		r.logger.Error("scanner error", "error", err)
	}
}

// RFC 5424 pattern: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
var rfc5424Pattern = regexp.MustCompile(`^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$`)

// RFC 3164 pattern: <PRI>TIMESTAMP HOSTNAME TAG MSG
var rfc3164Pattern = regexp.MustCompile(`^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$`)

func (r *SyslogReceiver) parseMessage(raw, sourceIP string, sourcePort int, protocol string) *SyslogMessage {
	msg := &SyslogMessage{
		RawMessage: raw,
		ReceivedAt: time.Now(),
		SourceIP:   sourceIP,
		SourcePort: sourcePort,
		Protocol:   protocol,
	}

	// Try RFC 5424 first
	if matches := rfc5424Pattern.FindStringSubmatch(raw); matches != nil {
		if err := r.parseRFC5424(msg, matches); err == nil {
			msg.RFC = "5424"
			return msg
		}
	}

	// Try RFC 3164
	if matches := rfc3164Pattern.FindStringSubmatch(raw); matches != nil {
		if err := r.parseRFC3164(msg, matches); err == nil {
			msg.RFC = "3164"
			return msg
		}
	}

	// Fallback: treat as plain message
	r.parseErrors.Add(1)
	msg.Message = raw
	msg.Timestamp = time.Now()
	msg.RFC = "unknown"
	return msg
}

func (r *SyslogReceiver) parseRFC5424(msg *SyslogMessage, matches []string) error {
	// Parse priority
	pri, _ := strconv.Atoi(matches[1])
	msg.Priority = pri
	msg.Facility = pri / 8
	msg.Severity = pri % 8

	// Version
	msg.Version, _ = strconv.Atoi(matches[2])

	// Timestamp
	if ts, err := time.Parse(time.RFC3339Nano, matches[3]); err == nil {
		msg.Timestamp = ts
	} else if ts, err := time.Parse(time.RFC3339, matches[3]); err == nil {
		msg.Timestamp = ts
	} else {
		msg.Timestamp = time.Now()
	}

	msg.Hostname = nilValue(matches[4])
	msg.AppName = nilValue(matches[5])
	msg.ProcID = nilValue(matches[6])
	msg.MsgID = nilValue(matches[7])

	// Parse structured data and message
	remaining := matches[8]
	if strings.HasPrefix(remaining, "[") {
		sdEnd := findSDEnd(remaining)
		if sdEnd > 0 {
			msg.StructData = parseStructuredData(remaining[:sdEnd])
			msg.Message = strings.TrimSpace(remaining[sdEnd:])
		}
	} else if remaining == "-" {
		msg.Message = ""
	} else {
		msg.Message = remaining
	}

	return nil
}

func (r *SyslogReceiver) parseRFC3164(msg *SyslogMessage, matches []string) error {
	// Parse priority
	pri, _ := strconv.Atoi(matches[1])
	msg.Priority = pri
	msg.Facility = pri / 8
	msg.Severity = pri % 8
	msg.Version = 0

	// Timestamp (assume current year)
	tsStr := matches[2]
	currentYear := time.Now().Year()
	if ts, err := time.Parse("Jan  2 15:04:05 2006", tsStr+" "+strconv.Itoa(currentYear)); err == nil {
		msg.Timestamp = ts
	} else if ts, err := time.Parse("Jan 2 15:04:05 2006", tsStr+" "+strconv.Itoa(currentYear)); err == nil {
		msg.Timestamp = ts
	} else {
		msg.Timestamp = time.Now()
	}

	msg.Hostname = matches[3]
	msg.AppName = matches[4]
	if len(matches) > 5 && matches[5] != "" {
		msg.ProcID = matches[5]
	}
	msg.Message = matches[len(matches)-1]

	return nil
}

func nilValue(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func findSDEnd(s string) int {
	depth := 0
	inQuote := false
	for i, c := range s {
		if c == '"' && (i == 0 || s[i-1] != '\\') {
			inQuote = !inQuote
		}
		if !inQuote {
			if c == '[' {
				depth++
			} else if c == ']' {
				depth--
				if depth == 0 {
					return i + 1
				}
			}
		}
	}
	return len(s)
}

func parseStructuredData(s string) map[string]map[string]string {
	result := make(map[string]map[string]string)

	// Simple parser for structured data
	// [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]
	sdPattern := regexp.MustCompile(`\[(\S+?)(?:\s+(.+?))?\]`)
	matches := sdPattern.FindAllStringSubmatch(s, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			sdID := match[1]
			params := make(map[string]string)

			if len(match) >= 3 && match[2] != "" {
				// Parse key="value" pairs
				paramPattern := regexp.MustCompile(`(\S+?)="([^"]*)"`)
				paramMatches := paramPattern.FindAllStringSubmatch(match[2], -1)
				for _, pm := range paramMatches {
					if len(pm) >= 3 {
						params[pm[1]] = pm[2]
					}
				}
			}

			result[sdID] = params
		}
	}

	return result
}
