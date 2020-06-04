package main

import (
	"fmt"
	dnstap "github.com/dnstap/golang-dnstap"
	influxdb2 "github.com/influxdata/influxdb-client-go"
	flag "github.com/spf13/pflag"
	"os"
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
)

func main() {
	flag.Usage = func() {
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
	flag.Parse()

	args := flag.Args()
	if len(args) != 2 {
		flag.Usage()
		os.Exit(0)
	}

	influxdb := args[0]
	name := args[1]

	options := influxdb2.DefaultOptions().
		SetLogLevel(flagLogLevel).
		SetBatchSize(flagBatchSize).
		SetFlushInterval(flagFlushIntervalMs).
		SetPrecision(time.Millisecond)
	influx := NewInfluxOutput(influxdb, flagAuthToken, flagOrg, flagBucket, flagMeasurement, flagBufferSize, options)
	defer influx.Close()
	go influx.RunOutputLoop()
	influx.LogErrors()

	if flagFile {
		input, err := dnstap.NewFrameStreamInputFromFilename(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnstap: Failed to open input file %s: %v\n", name, err)
			os.Exit(1)
		}
		go input.ReadInto(influx.GetOutputChannel())
		input.Wait()
	} else {
		input, err := dnstap.NewFrameStreamSockInputFromPath(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnstap: Failed to open unix socket %s: %v\n", name, err)
			os.Exit(1)
		}
		go input.ReadInto(influx.GetOutputChannel())
		input.Wait()
	}

	os.Exit(0)
}
