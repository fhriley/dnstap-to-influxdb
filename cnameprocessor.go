package main

import (
	"bufio"
	"context"
	"fmt"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

type CnameCommand int

const (
	DnsTapCommand      CnameCommand = 0
	UpdateListsCommand              = 1
)

type UpdateCommand int

const (
	UpdateAllCommand   UpdateCommand = 0
	UpdateBlockCommand               = 1
	UpdateWhiteCommand               = 2
	UpdateBlackCommand               = 3
)

type Command struct {
	command        CnameCommand
	message        *Message
	blockedDomains *map[string]bool
}

type CnameProcessor struct {
	messages       chan *Message
	commands       chan *Command
	blockedFile    string
	whitelistFile  string
	blacklistFile  string
	blockedCnames  *map[string]string
	blockedDomains *map[string]bool
	unbound        *Unbound
	httpServer     *http.Server
	httpMutex      sync.Mutex
}

func addKeys(destMap *map[string]bool, keysMap *map[string]bool) {
	for key := range *keysMap {
		(*destMap)[key] = true
	}
}

func removeKeys(destMap *map[string]bool, keysMap *map[string]bool) {
	for key := range *keysMap {
		delete(*destMap, key)
	}
}

func NewCnameProcessor(blockedFile, whitelistFile, blacklistFile string, bufferSize, port uint) *CnameProcessor {
	blockedDomains, err := getBlockedDomains(blockedFile, whitelistFile, blacklistFile)
	if err != nil {
		log.WithError(err).Fatal("Failed to get blocked domains")
	}
	blockedCnames := make(map[string]string)

	return &CnameProcessor{
		messages:       make(chan *Message, bufferSize),
		commands:       make(chan *Command, bufferSize),
		blockedFile:    blockedFile,
		blacklistFile:  blacklistFile,
		whitelistFile:  whitelistFile,
		blockedCnames:  &blockedCnames,
		blockedDomains: blockedDomains,
		unbound:        NewUnbound(),
		httpServer:     &http.Server{Addr: fmt.Sprintf(":%d", port)},
	}
}

func getBlockedDomains(blockedFile, whitelistFile, blacklistFile string) (*map[string]bool, error) {
	whitelistDomains, err := loadRpzFile(whitelistFile)
	if err != nil {
		return whitelistDomains, err
	}
	blacklistDomains, err := loadRpzFile(blacklistFile)
	if err != nil {
		return blacklistDomains, err
	}
	blockedDomains, err := loadRpzFile(blockedFile)
	if err != nil {
		return blockedDomains, err
	}
	addKeys(blockedDomains, blacklistDomains)
	removeKeys(blockedDomains, whitelistDomains)
	return blockedDomains, nil
}

func (proc *CnameProcessor) GetChannel() chan *Message {
	return proc.messages
}

func (proc *CnameProcessor) Run(wg *sync.WaitGroup) {
	childrenWg := sync.WaitGroup{}
	childrenWg.Add(3)

	go proc.processCommands(&childrenWg)
	go proc.runUpdateListener(&childrenWg)
	go proc.unbound.Run(&childrenWg)

	for message := range proc.messages {
		proc.processMessage(message)
	}

	_ = proc.httpServer.Shutdown(context.TODO())
	close(proc.commands)
	close(proc.unbound.GetChannel())
	childrenWg.Wait()
	wg.Done()
}

func (proc *CnameProcessor) runUpdateListener(wg *sync.WaitGroup) {
	http.HandleFunc("/updateAll", func(w http.ResponseWriter, req *http.Request) {
		proc.updateHandler(w, req, UpdateAllCommand)
	})
	http.HandleFunc("/updateBlock", func(w http.ResponseWriter, req *http.Request) {
		proc.updateHandler(w, req, UpdateBlockCommand)
	})
	http.HandleFunc("/updateWhite", func(w http.ResponseWriter, req *http.Request) {
		proc.updateHandler(w, req, UpdateWhiteCommand)
	})
	http.HandleFunc("/updateBlack", func(w http.ResponseWriter, req *http.Request) {
		proc.updateHandler(w, req, UpdateBlackCommand)
	})
	if err := proc.httpServer.ListenAndServe(); err != http.ErrServerClosed {
		log.WithError(err).Fatal("ListenAndServe() failed")
	}
	wg.Done()
}

//noinspection GoUnusedParameter
func (proc *CnameProcessor) updateHandler(w http.ResponseWriter, req *http.Request, command UpdateCommand) {
	if req.Method == http.MethodPost {
		proc.httpMutex.Lock()
		defer proc.httpMutex.Unlock()

		log.Infof("CNAME handler got update command: %d", command)

		blockedDomains, err := getBlockedDomains(proc.blockedFile, proc.whitelistFile, proc.blacklistFile)
		if err != nil {
			http.Error(w, fmt.Sprintf("something went wrong: %s", err), http.StatusInternalServerError)
		} else {
			cmdObj := Command{UpdateListsCommand, nil, blockedDomains}
			proc.commands <- &cmdObj
			w.WriteHeader(http.StatusOK)
		}

		log.Info("CNAME handler finished update")
	} else {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
	}
}

func loadRpzFile(path string) (*map[string]bool, error) {
	domains := make(map[string]bool)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.WithError(err).Warningf("%s doesn't exist", path)
		return &domains, err
	}

	file, err := os.Open(path)
	if err != nil {
		log.WithError(err).Errorf("Failed to open %s", path)
		return &domains, err
	}
	//noinspection GoUnhandledErrorResult
	defer file.Close()

	re := regexp.MustCompile(`^(local-zone:\s*")?(([a-z0-9]+([-a-z0-9]+)*\.)+[a-z]{2,}\.?)`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		match := re.FindStringSubmatch(line)
		if match != nil {
			domain := match[2]
			if !strings.HasSuffix(domain, ".") {
				domain += "."
			}
			domains[domain] = true
		}
	}
	if err := scanner.Err(); err != nil {
		log.WithError(err).Errorf("Failed to read %s", file.Name())
		return &domains, err
	}

	return &domains, nil
}

func (proc *CnameProcessor) processMessage(message *Message) {
	// There is a second level in the pipeline so that when block list updates come in,
	// we can inject the update into the pipeline. By doing this, we avoid having to
	// do any locking when using the block and cname lists.
	command := Command{DnsTapCommand, message, nil}
	proc.commands <- &command
}

func (proc *CnameProcessor) processCommands(wg *sync.WaitGroup) {
	for command := range proc.commands {
		switch command.command {
		case DnsTapCommand:
			proc.processDnstapMessage(command.message)
		case UpdateListsCommand:
			proc.processUpdateLists(command.blockedDomains)
		default:
			log.Warnf("Got invalid command: %s", command.command)
		}
	}
	wg.Done()
}

func (proc *CnameProcessor) processUpdateLists(blockedDomains *map[string]bool) {
	// Remove cnames that are no longer blocked
	for qname, cname := range *proc.blockedCnames {
		if !(*blockedDomains)[cname] {
			log.Infof("Removing block of \"%s\" because cname \"%s\" is no longer blocked", qname, cname)
			proc.unbound.GetChannel() <- &UnboundCommandMessage{
				cmd:    ZoneRemove,
				domain: qname,
			}
			delete(*proc.blockedCnames, qname)
		}
	}

	proc.blockedDomains = blockedDomains
}

func (proc *CnameProcessor) processDnstapMessage(message *Message) {
	if message.dnsMessage != nil && len(message.dnsMessage.Answer) > 0 {
		qname := message.dnsMessage.Question[0].Name
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
				(*cnames)[cname.Hdr.Name] = cname.Target
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
				log.Infof("Blocking \"%s\" because of blocked cname \"%s\"", qname, cname)

				(*proc.blockedCnames)[qname] = cname
				(*proc.blockedDomains)[qname] = true

				proc.unbound.GetChannel() <- &UnboundCommandMessage{
					cmd:    ZoneAdd,
					domain: qname,
				}

				break
			} else {
				check = cname
			}
		}
	}
}
