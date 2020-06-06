package main

import (
	"fmt"
	dnstap "github.com/dnstap/golang-dnstap"
	influxdb2 "github.com/influxdata/influxdb-client-go"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"os"
	"sync"
	"time"
)

var (
	flagLogLevel        uint
	flagFile            bool
	flagMeasurement     string
	flagBucket          string
	flagAuthToken       string
	flagOrg             string
	flagBatchSize       uint
	flagBufferSize      uint
	flagFlushIntervalMs uint
	flagBlockFile       string
	flagWhitelistFile   string
	flagBlacklistFile   string
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)

	flag.Usage = func() {
		//noinspection GoUnhandledErrorResult
		fmt.Fprintf(os.Stderr, "%s <influxdb_url> <sock_or_file>\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.UintVarP(&flagLogLevel, "loglevel", "l", 1, "turn on verbose logging")
	flag.BoolVarP(&flagFile, "file", "f", false, "input is a file rather than a unix socket")
	flag.StringVarP(&flagMeasurement, "measurement", "m", "queries", "the influxdb measurement name")
	flag.StringVarP(&flagBucket, "bucket", "b", "dns", "the influxdb bucket name")
	flag.StringVarP(&flagAuthToken, "token", "t", "", "the influxdb auth token")
	flag.StringVarP(&flagOrg, "org", "o", "", "the influxdb org")
	flag.UintVarP(&flagBatchSize, "batch", "c", 1000, "the write batch size")
	flag.UintVarP(&flagBufferSize, "buffer", "r", 1000, "the write buffer size")
	flag.UintVarP(&flagFlushIntervalMs, "flush", "u", 1000, "the write flush interval in ms")
	flag.StringVar(&flagBlockFile, "block", "/web/hblock.rpz", "the hblock rpz file")
	flag.StringVar(&flagWhitelistFile, "white", "/web/whitelist.rpz", "the whitelist rpz file")
	flag.StringVar(&flagBlacklistFile, "black", "/web/blacklist.rpz", "the blacklist rpz file")
	flag.Parse()

	args := flag.Args()
	if len(args) != 2 {
		flag.Usage()
		os.Exit(0)
	}

	influxdb := args[0]
	name := args[1]

	decoder := NewDnsTapDecoder(flagBufferSize)

	options := influxdb2.DefaultOptions().
		SetLogLevel(flagLogLevel).
		SetBatchSize(flagBatchSize).
		SetFlushInterval(flagFlushIntervalMs).
		SetPrecision(time.Millisecond)
	influx := NewInfluxProcessor(influxdb, flagAuthToken, flagOrg, flagBucket, flagMeasurement, flagBufferSize, options)
	influx.LogErrors()

	cnames := NewCnameProcessor(flagBlockFile, flagWhitelistFile, flagBlacklistFile, flagBufferSize)

	decoder.AddProcessor(influx)
	decoder.AddProcessor(cnames)

	var wg sync.WaitGroup
	wg.Add(3)

	go influx.Run(&wg)
	go cnames.Run(&wg)
	go decoder.Run(&wg)

	if flagFile {
		input, err := dnstap.NewFrameStreamInputFromFilename(name)
		if err != nil {
			log.Fatalf("dnstap: Failed to open input file %s: %v", name, err)
		}
		go input.ReadInto(decoder.GetChannel())
		input.Wait()
	} else {
		input, err := dnstap.NewFrameStreamSockInputFromPath(name)
		if err != nil {
			//noinspection GoUnhandledErrorResult
			log.Fatalf("dnstap: Failed to open unix socket %s: %v", name, err)
		}
		go input.ReadInto(decoder.GetChannel())
		input.Wait()
	}

	close(decoder.GetChannel())
	wg.Wait()
	os.Exit(0)
}
