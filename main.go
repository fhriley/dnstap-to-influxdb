package main

import (
	"fmt"
	dnstap "github.com/dnstap/golang-dnstap"
	influxdb2 "github.com/influxdata/influxdb-client-go"
	flag "github.com/spf13/pflag"
	"os"
)

var (
	flagVerbose     bool
	flagFile        bool
	flagMeasurement string
	flagBucket      string
	flagAuthToken   string
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s <influxdb_url> <sock_or_file>\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.BoolVarP(&flagVerbose, "verbose", "v", false, "turn on verbose logging")
	flag.BoolVarP(&flagFile, "file", "f", false, "input is a file rather than a unix socket")
	flag.StringVarP(&flagMeasurement, "measurement", "m", "queries", "the influxdb measurement name")
	flag.StringVarP(&flagBucket, "bucket", "b", "dns/autogen", "the influxdb bucket name")
	flag.StringVarP(&flagAuthToken, "token", "t", "", "the influxdb auth token")
	flag.Parse()

	args := flag.Args()
	if len(args) != 2 {
		flag.Usage()
		os.Exit(0)
	}

	influxdb := args[0]
	name := args[1]

	logLevel := 1
	if flagVerbose {
		logLevel = 3
	}
	options := influxdb2.DefaultOptions().SetLogLevel(uint(logLevel))
	influx := NewInfluxOutput(influxdb, flagAuthToken, "", flagBucket, flagMeasurement, options)
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