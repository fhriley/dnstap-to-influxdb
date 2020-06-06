package main

import (
	log "github.com/sirupsen/logrus"
	"os/exec"
	"sync"
)

type UnboundCommand int

type UnboundProcessor interface {
	GetChannel() chan *UnboundCommandMessage
	Run(wg *sync.WaitGroup)
}

const (
	ZoneAdd    UnboundCommand = 1
	ZoneRemove                = 2
)

type UnboundCommandMessage struct {
	cmd    UnboundCommand
	domain string
}

type Unbound struct {
	messages chan *UnboundCommandMessage
}

func NewUnbound() *Unbound {
	return &Unbound{
		messages: make(chan *UnboundCommandMessage, 1000),
	}
}

func (unbound *Unbound) GetChannel() chan *UnboundCommandMessage {
	return unbound.messages
}

func (unbound *Unbound) Run(wg *sync.WaitGroup) {
	for message := range unbound.messages {
		var cmd *exec.Cmd
		switch message.cmd {
		case ZoneAdd:
			cmd = exec.Command("/opt/unbound/sbin/unbound-control", "local_zone", message.domain, "always_nxdomain")
		case ZoneRemove:
			cmd = exec.Command("/opt/unbound/sbin/unbound-control", "local_zone_remove", message.domain)
		default:
			log.Warnf("Got invalid command: %s", message.cmd)
			continue
		}
		err := cmd.Run()
		if err != nil {
			log.WithError(err).Errorf("command \"%s\" failed", cmd)
		}
	}
	wg.Done()
}
