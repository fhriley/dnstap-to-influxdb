package main

import (
	"context"
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/golang/protobuf/proto"
	"github.com/miekg/dns"
	"log"
	"net"
	"sync"
	"time"
)

//noinspection GoUnusedExportedType
type Decoder interface {
	GetChannel() chan []byte
	AddProcessor(proc Processor)
	Run(wg *sync.WaitGroup)
}

type hostItem struct {
	host      string
	timestamp time.Time
}

type DnsTapDecoder struct {
	channel    chan []byte
	processors []Processor
	ipToHost   map[string]*hostItem
	resolver   net.Resolver
}

func NewDnsTapDecoder(resolver string, bufferSize uint) *DnsTapDecoder {
	return &DnsTapDecoder{
		channel:    make(chan []byte, bufferSize),
		processors: make([]Processor, 0),
		ipToHost:   make(map[string]*hostItem),
		resolver: net.Resolver{
			PreferGo:     true,
			StrictErrors: false,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * 1000,
				}
				return d.DialContext(ctx, "udp", resolver)
			},
		},
	}
}

func (dec *DnsTapDecoder) GetChannel() chan []byte {
	return dec.channel
}

func (dec *DnsTapDecoder) AddProcessor(proc Processor) {
	dec.processors = append(dec.processors, proc)
}

func getTime(sec *uint64, nsec *uint32) time.Time {
	if sec != nil && nsec != nil {
		return time.Unix(int64(*sec), int64(*nsec)).UTC()
	} else {
		return time.Now().UTC()
	}
}

func getDnsMsg(msg []byte) *dns.Msg {
	if msg != nil {
		m := new(dns.Msg)
		err := m.Unpack(msg)
		if err == nil {
			return m
		}
	}
	return nil
}

func (dec *DnsTapDecoder) getHost(addr []byte) string {
	if addr != nil {
		now := time.Now()
		ip := net.IP(addr).String()
		host, exists := dec.ipToHost[ip]
		if !exists || host.timestamp.Add(time.Duration(time.Hour)).Before(now) {
			hosts, err := dec.resolver.LookupAddr(context.Background(), ip)
			if err == nil && len(hosts) > 0 && hosts[0] != "" {
				host = &hostItem{hosts[0], now}
			} else if host == nil {
				host = &hostItem{ip, now}
			}
			dec.ipToHost[ip] = host
		}
		return host.host
	}
	return ""
}

func (dec *DnsTapDecoder) Run(wg *sync.WaitGroup) {
	for frame := range dec.channel {
		dt := &dnstap.Dnstap{}

		// decode the protobuf
		if err := proto.Unmarshal(frame, dt); err != nil {
			log.Fatalf("proto.Unmarshal() failed: %s\n", err)
		}

		if *dt.Type == dnstap.Dnstap_MESSAGE {
			dnstapMessage := dt.Message
			var timestamp time.Time
			var dnsMsg *dns.Msg

			// decode the dns info
			switch *dnstapMessage.Type {
			case dnstap.Message_AUTH_QUERY,
				dnstap.Message_CLIENT_QUERY,
				dnstap.Message_FORWARDER_QUERY,
				dnstap.Message_RESOLVER_QUERY,
				dnstap.Message_STUB_QUERY,
				dnstap.Message_TOOL_QUERY:
				timestamp = getTime(dnstapMessage.QueryTimeSec, dnstapMessage.QueryTimeNsec)
				dnsMsg = getDnsMsg(dnstapMessage.QueryMessage)

			case dnstap.Message_AUTH_RESPONSE,
				dnstap.Message_CLIENT_RESPONSE,
				dnstap.Message_FORWARDER_RESPONSE,
				dnstap.Message_RESOLVER_RESPONSE,
				dnstap.Message_STUB_RESPONSE,
				dnstap.Message_TOOL_RESPONSE:
				timestamp = getTime(dnstapMessage.ResponseTimeSec, dnstapMessage.ResponseTimeNsec)
				dnsMsg = getDnsMsg(dnstapMessage.ResponseMessage)

			default:
				timestamp = getTime(nil, nil)
				dnsMsg = getDnsMsg(nil)
			}

			host := dec.getHost(dnstapMessage.QueryAddress)

			// create a processor message
			message := &Message{timestamp: timestamp, dnstapMessage: dnstapMessage, dnsMessage: dnsMsg, host: host}

			// send the message to all configured processors
			for _, proc := range dec.processors {
				proc.GetChannel() <- message
			}
		}
	}

	for _, proc := range dec.processors {
		close(proc.GetChannel())
	}
	wg.Done()
}
