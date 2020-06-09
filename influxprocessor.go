package main

import (
	dnstap "github.com/dnstap/golang-dnstap"
	influxdb2 "github.com/influxdata/influxdb-client-go"
	"github.com/influxdata/influxdb-client-go/api"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"net"
	"strconv"
	"sync"
)

type InfluxProcessor struct {
	client      influxdb2.Client
	writeApi    api.WriteApi
	messages    chan *Message
	wait        chan bool
	ipToHost    map[string]string
	measurement string
}

func NewInfluxProcessor(serverUrl string, authToken string, org string, bucket string, measurement string, bufferSize uint, options *influxdb2.Options) *InfluxProcessor {
	client := influxdb2.NewClientWithOptions(serverUrl, authToken, options)
	return &InfluxProcessor{
		client:      client,
		writeApi:    client.WriteApi(org, bucket),
		messages:    make(chan *Message, bufferSize),
		wait:        make(chan bool),
		ipToHost:    make(map[string]string),
		measurement: measurement,
	}
}

func (influx *InfluxProcessor) GetWriteApi() *api.WriteApi {
	return &influx.writeApi
}

func (influx *InfluxProcessor) GetChannel() chan *Message {
	return influx.messages
}

func (influx *InfluxProcessor) Run(wg *sync.WaitGroup) {
	for message := range influx.messages {
		influx.writePoints(message)
	}
	influx.writeApi.Flush()
	influx.client.Close()
	wg.Done()
}

func (influx *InfluxProcessor) writePoints(msg *Message) {
	point := influxdb2.NewPointWithMeasurement(influx.measurement).AddTag("tap_type", msg.dnstapMessage.Type.String())
	if msg.dnstapMessage.QueryAddress != nil {
		point.AddTag("qaddress", net.IP(msg.dnstapMessage.QueryAddress).String())
	}
	if len(msg.host) > 0 {
		point.AddTag("qhost", msg.host)
	}

	point.SetTime(msg.timestamp)

	switch *msg.dnstapMessage.Type {
	case dnstap.Message_AUTH_RESPONSE,
		dnstap.Message_CLIENT_RESPONSE,
		dnstap.Message_FORWARDER_RESPONSE,
		dnstap.Message_RESOLVER_RESPONSE,
		dnstap.Message_STUB_RESPONSE,
		dnstap.Message_TOOL_RESPONSE:
		if msg.dnstapMessage.ResponseAddress != nil {
			point.AddTag("raddress", net.IP(msg.dnstapMessage.ResponseAddress).String())
		}
		if msg.dnsMessage != nil {
			if msg.dnsMessage.Question != nil && len(msg.dnsMessage.Question) > 0 &&
				(msg.dnsMessage.Question[0].Qtype == dns.TypeA || msg.dnsMessage.Question[0].Qtype == dns.TypeAAAA) &&
				msg.dnsMessage.Rcode == dns.RcodeSuccess && len(msg.dnsMessage.Answer) == 0 {
				point.AddField("nodata", true)
			}
		}
	}

	if msg.dnsMessage != nil {
		point.AddField("id", int(msg.dnsMessage.MsgHdr.Id))
		point.AddTag("status", dns.RcodeToString[msg.dnsMessage.MsgHdr.Rcode])
		if msg.dnsMessage.Question != nil && len(msg.dnsMessage.Question) > 0 {
			point.AddTag("qname", msg.dnsMessage.Question[0].Name)
			point.AddTag("qtype", dns.Type(msg.dnsMessage.Question[0].Qtype).String())
		}
	}

	if msg.dnstapMessage.SocketProtocol != nil {
		point.AddTag("protocol", msg.dnstapMessage.SocketProtocol.String())
	}

	if msg.dnstapMessage.QueryZone != nil {
		name, _, err := dns.UnpackDomainName(msg.dnstapMessage.QueryZone, 0)
		if err == nil {
			point.AddTag("query_zone", strconv.Quote(name))
		}
	}

	if msg.dnstapMessage.SocketFamily != nil {
		point.AddField("family", msg.dnstapMessage.SocketFamily.String())
	}

	if msg.dnstapMessage.QueryPort != nil {
		point.AddField("qport", int(*msg.dnstapMessage.QueryPort))
	}

	influx.writeApi.WritePoint(point)
}

func (influx *InfluxProcessor) LogErrors() {
	errorsCh := influx.writeApi.Errors()
	go func() {
		for err := range errorsCh {
			log.WithError(err).Error("write error")
		}
	}()
}
