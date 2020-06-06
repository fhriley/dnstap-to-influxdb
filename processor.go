package main

import (
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"sync"
	"time"
)

type Message struct {
	timestamp     time.Time
	dnstapMessage *dnstap.Message
	dnsMessage    *dns.Msg
	host          string
}

type Processor interface {
	GetChannel() chan *Message
	Run(wg *sync.WaitGroup)
}
