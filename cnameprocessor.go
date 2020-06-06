package main

import (
	"bufio"
	"fmt"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"os"
	"regexp"
	"strings"
	"sync"
)

type CnameProcessor struct {
	messages       chan *Message
	blockedCnames  *map[string]string
	blockedDomains *map[string]bool
	unbound        *Unbound
}

func addKeys(destMap *map[string]bool, keysMap *map[string]bool) {
	for key, _ := range *keysMap {
		(*destMap)[key] = true
	}
}

func removeKeys(destMap *map[string]bool, keysMap *map[string]bool) {
	for key, _ := range *keysMap {
		delete(*destMap, key)
	}
}

func NewCnameProcessor(blockedFile string, whitelistFile string, blacklistFile string, bufferSize uint) *CnameProcessor {
	// build a map of blocked domains
	whitelistDomains := loadRpzFile(whitelistFile)
	blacklistDomains := loadRpzFile(blacklistFile)
	blockedDomains := loadRpzFile(blockedFile)
	addKeys(blockedDomains, blacklistDomains)
	removeKeys(blockedDomains, whitelistDomains)

	blockedCnames := make(map[string]string)

	return &CnameProcessor{
		messages:       make(chan *Message, bufferSize),
		blockedCnames:  &blockedCnames,
		blockedDomains: blockedDomains,
		unbound:        NewUnbound(),
	}
}

func (proc *CnameProcessor) GetChannel() chan *Message {
	return proc.messages
}

func (proc *CnameProcessor) Run(wg *sync.WaitGroup) {
	for message := range proc.messages {
		proc.processMessage(message)
	}
	proc.unbound.Destroy()
	wg.Done()
}

func loadRpzFile(path string) *map[string]bool {
	domains := make(map[string]bool)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.WithFields(log.Fields{
			"file": path,
		}).Warning("Doesn't exist")
		return &domains
	}

	file, err := os.Open(path)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"file": path,
		}).Error("Failed to open file")
		return &domains
	}
	defer file.Close()

	re := regexp.MustCompile(`^(local-zone:\s+")?(([a-z0-9]+([-a-z0-9]+)*\.)+[a-z]{2,})`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		match := re.FindStringSubmatch(line)
		if match != nil {
			domains[match[2]] = true
		}
	}
	if err := scanner.Err(); err != nil {
		log.WithError(err).WithFields(log.Fields{
			"file": file.Name(),
		}).Error("Failed to read file")
		return &domains
	}

	return &domains
}

func (proc *CnameProcessor) processMessage(message *Message) {
	if message.dnsMessage != nil && len(message.dnsMessage.Answer) > 0 {
		qname := strings.TrimSuffix(message.dnsMessage.Question[0].Name, ".")
		if (*proc.blockedDomains)[qname] {
			return
		}

		// build the chain
		var cnames *map[string]string
		for _, rr := range message.dnsMessage.Answer {
			if rr.Header().Rrtype == dns.TypeCNAME {
				if cnames == nil {
					cnames = &map[string]string{}
				}
				cname, _ := rr.(*dns.CNAME)
				(*cnames)[strings.TrimSuffix(cname.Hdr.Name, ".")] = strings.TrimSuffix(cname.Target, ".")
			}
		}

		if cnames == nil {
			return
		}

		// walk the chain
		check := qname
		for {
			cname := (*cnames)[check]
			if len(cname) == 0 {
				break
			}
			if (*proc.blockedDomains)[cname] {
				log.WithFields(log.Fields{
					"qname": qname,
					"cname": cname,
				}).Info("Blocking qname because of blocked cname")

				(*proc.blockedCnames)[qname] = cname
				(*proc.blockedDomains)[qname] = true

				zone := fmt.Sprintf("%s.", qname)
				err := proc.unbound.ZoneAdd(zone, "always_nxdomain")
				if err != nil {
					log.WithError(err).Error("unbound.ZoneAdd failed")
				}

				break
			} else {
				check = cname
			}
		}
	}
}
