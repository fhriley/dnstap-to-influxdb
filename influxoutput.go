package main

import (
	"fmt"
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/golang/protobuf/proto"
	influxdb2 "github.com/influxdata/influxdb-client-go"
	"github.com/influxdata/influxdb-client-go/api"
	"github.com/influxdata/influxdb-client-go/api/write"
	"github.com/miekg/dns"
	"log"
	"net"
	"strconv"
	"time"
)

type InfluxOutput struct {
	client      influxdb2.Client
	writeApi    api.WriteApi
	data        chan []byte
	wait        chan bool
	ipToHost    map[string]string
	measurement string
}

func NewInfluxOutput(serverUrl string, authToken string, org string, bucket string, measurement string, bufferSize uint, options *influxdb2.Options) *InfluxOutput {
	client := influxdb2.NewClientWithOptions(serverUrl, authToken, options)
	return &InfluxOutput{
		client:      client,
		writeApi:    client.WriteApi(org, bucket),
		data:        make(chan []byte, bufferSize),
		wait:        make(chan bool),
		ipToHost:    make(map[string]string),
		measurement: measurement,
	}
}

func (influx *InfluxOutput) GetOutputChannel() chan []byte {
	return influx.data
}

func (influx *InfluxOutput) Close() {
	close(influx.data)
	<-influx.wait
	influx.writeApi.Flush()
	influx.client.Close()
}

func setTime(point *write.Point, sec *uint64, nsec *uint32) {
	if sec != nil && nsec != nil {
		point.SetTime(time.Unix(int64(*sec), int64(*nsec)).UTC())
	}
}

func addTagAddress(point *write.Point, tag string, addr []byte) {
	if addr != nil {
		point.AddTag(tag, net.IP(addr).String())
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

func addDnsMsg(point *write.Point, msg *dns.Msg) {
	if msg != nil {
		point.AddField("id", int(msg.MsgHdr.Id))
		point.AddTag("status", dns.RcodeToString[msg.MsgHdr.Rcode])
		if len(msg.Question) > 0 {
			point.AddTag("qname", msg.Question[0].Name)
			point.AddTag("qtype", dns.Type(msg.Question[0].Qtype).String())
		}
	}
}

func getCnames(msg *dns.Msg) map[string]string {
	cnames := make(map[string]string)
	if len(msg.Answer) > 0 {
		for _, rr := range msg.Answer {
			if rr.Header().Rrtype == dns.TypeCNAME {
				cname, _ := rr.(*dns.CNAME)
				cnames[cname.Hdr.Name] = cname.Target
			}
		}
	}
	return cnames
}

func (influx *InfluxOutput) getHost(addr []byte) string {
	if addr != nil {
		ip := net.IP(addr).String()
		host, exists := influx.ipToHost[ip]
		if !exists {
			hosts, err := net.LookupAddr(ip)
			if err == nil && len(hosts) > 0 && hosts[0] != "" {
				host = hosts[0]
			} else {
				host = ip
			}
			influx.ipToHost[ip] = host
		}
		return host
	}
	return ""
}

func (influx *InfluxOutput) writePoints(msg *dnstap.Message) {
	point := influxdb2.NewPointWithMeasurement(influx.measurement).AddTag("tap_type", msg.Type.String())
	host := influx.getHost(msg.QueryAddress)
	if len(host) > 0 {
		point.AddTag("qhost", host)
	}

	var dnsMsg *dns.Msg

	switch *msg.Type {
	case dnstap.Message_AUTH_QUERY,
		dnstap.Message_CLIENT_QUERY,
		dnstap.Message_FORWARDER_QUERY,
		dnstap.Message_RESOLVER_QUERY,
		dnstap.Message_STUB_QUERY,
		dnstap.Message_TOOL_QUERY:
		setTime(point, msg.QueryTimeSec, msg.QueryTimeNsec)
		dnsMsg = getDnsMsg(msg.QueryMessage)

	case dnstap.Message_AUTH_RESPONSE,
		dnstap.Message_CLIENT_RESPONSE,
		dnstap.Message_FORWARDER_RESPONSE,
		dnstap.Message_RESOLVER_RESPONSE,
		dnstap.Message_STUB_RESPONSE,
		dnstap.Message_TOOL_RESPONSE:
		setTime(point, msg.ResponseTimeSec, msg.ResponseTimeNsec)
		addTagAddress(point, "raddress", msg.ResponseAddress)
		dnsMsg = getDnsMsg(msg.ResponseMessage)

	default:
		point.SetTime(time.Now().UTC())
	}

	if dnsMsg != nil {
		addDnsMsg(point, dnsMsg)
		//cnames := getCnames(dnsMsg)
		//if len(cnames) != 0 {
		//	fmt.Println(cnames)
		//	fmt.Println(dnsMsg)
		//}
	}

	if msg.SocketProtocol != nil {
		point.AddTag("protocol", msg.SocketProtocol.String())
	}

	if msg.QueryZone != nil {
		name, _, err := dns.UnpackDomainName(msg.QueryZone, 0)
		if err == nil {
			point.AddTag("query_zone", strconv.Quote(name))
		}
	}

	if msg.SocketFamily != nil {
		point.AddField("family", msg.SocketFamily.String())
	}

	if msg.QueryPort != nil {
		point.AddField("qport", int(*msg.QueryPort))
	}

	influx.writeApi.WritePoint(point)
}

func (influx *InfluxOutput) RunOutputLoop() {
	dt := &dnstap.Dnstap{}
	for frame := range influx.data {
		if err := proto.Unmarshal(frame, dt); err != nil {
			log.Fatalf("dnstap.TextOutput: proto.Unmarshal() failed: %s\n", err)
			break
		}
		if *dt.Type == dnstap.Dnstap_MESSAGE {
			influx.writePoints(dt.Message)
		}
	}
	close(influx.wait)
}

func (influx *InfluxOutput) LogErrors() {
	errorsCh := influx.writeApi.Errors()
	go func() {
		for err := range errorsCh {
			fmt.Printf("write error: %s\n", err.Error())
		}
	}()
}
