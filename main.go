package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/czerwonk/ping_exporter/config"
	"github.com/czerwonk/ping_exporter/pkg/log"
	"github.com/digineo/go-ping"
	mon "github.com/digineo/go-ping/monitor"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"net"
	"os"
	"strings"
	"time"
)

const version string = "0.0.1"

var (
	rootCmd = &cobra.Command{
		Use:   "ping_collector",
		Short: "ping_collector",
		Long:  "ping_collector",
		Args:  cobra.MinimumNArgs(0),
		Run:   rootRun,
	}
	Logger          = log.InitLogger()
	rttMetricsScale = rttInMills
)

func init() {

	rootCmd.Flags().String("version", version, "Print version information.")
	rootCmd.Flags().String("config.path", "", "Path to config file.")
	rootCmd.Flags().Duration("ping.interval", 5*time.Second, "Interval between pings.")
	rootCmd.Flags().Duration("ping.timeout", 4*time.Second, "Timeout for pings.")
	rootCmd.Flags().Uint16("ping.size", 56, "Size of ICMP payload.")
	rootCmd.Flags().Int("ping.history-size", 10, "Number of pings to keep in history.")
	rootCmd.Flags().Duration("dns.refresh", 1*time.Minute, "Interval for refreshing DNS records and updating targets accordingly (0 if disabled)")
	rootCmd.Flags().String("dns.nameserver", "", "Nameserver to use for DNS lookups (empty to use system default)")
	rootCmd.Flags().Bool("options.disableIPv6", false, "Prohibits DNS resolved IPv6 addresses")
	rootCmd.Flags().Bool("options.disableIPv4", false, "Prohibits DNS resolved IPv4 addresses")
	rootCmd.Flags().String("log.level", "info", "Only log messages with the given severity or above. Valid levels: [debug, info, warn, error, fatal]")
	rootCmd.Flags().String("ts.tailnet", "", "tailnet name")
	rootCmd.Flags().String("metrics.rttunit", "s", "Export ping results as either seconds (default), or milliseconds (deprecated), or both (for migrations). Valid choices: [s, ms, both]")
	rootCmd.Flags().String("outfile", "", "Output file for metrics. Default is stdout")

}

func rootRun(cmd *cobra.Command, args []string) {

	if showVersion, _ := cmd.Flags().GetBool("version"); showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	logLevel, _ := cmd.Flags().GetString("log.level")
	log.SetLogLevel(logLevel)
	rttMode, _ := cmd.Flags().GetString("metrics.rttunit")
	if rttMetricsScale = rttUnitFromString(rttMode); rttMetricsScale == rttInvalid {
		Logger.Fatal("metrics.rttunit must be `ms` for millis, or `s` for seconds, or `both`")
	}
	Logger.Sugar().Info("rttMetricsScale", rttMetricsScale)

	configFile, _ := cmd.Flags().GetString("config.path")

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		Logger.Fatal("Error loading config", zap.Error(err))
	}

	if cfg.Ping.History < 1 {
		Logger.Fatal("ping.history-size must be greater than 0")
	}

	if cfg.Ping.Size > 65500 {
		Logger.Fatal("ping.size must be less than 65500")
	}

	if len(cfg.Targets) == 0 {
		Logger.Fatal("No targets configured")
	}

	m, err := startMonitor(cfg)
	if err != nil {
		Logger.Error("Error starting monitor", zap.Error(err))
		os.Exit(2)
	}

	Logger.Info("Starting ping_exporter", zap.String("version", version))
	if outfile, _ := cmd.Flags().GetString("outfile"); outfile != "" {
		err := os.WriteFile(outfile, []byte(printMetrics(cfg, m)), 0644)
		if err != nil {
			Logger.Error("cannot write to file", zap.Error(err))
		}
	} else {
		fmt.Println(printMetrics(cfg, m))
	}
}

func startMonitor(cfg *config.Config) (*mon.Monitor, error) {
	resolver := setupResolver(cfg)
	var bind4, bind6 string
	if ln, err := net.Listen("tcp4", "127.0.0.1:0"); err == nil {
		// ipv4 enabled
		ln.Close()
		bind4 = "0.0.0.0"
	}
	if ln, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		// ipv6 enabled
		ln.Close()
		bind6 = "::"
	}
	pinger, err := ping.New(bind4, bind6)
	if err != nil {
		return nil, fmt.Errorf("cannot start monitoring: %w", err)
	}

	if pinger.PayloadSize() != cfg.Ping.Size {
		pinger.SetPayloadSize(cfg.Ping.Size)
	}

	monitor := mon.New(pinger,
		cfg.Ping.Interval.Duration(),
		cfg.Ping.Timeout.Duration())
	monitor.HistorySize = cfg.Ping.History

	targets := make([]*target, len(cfg.Targets))
	for i, t := range cfg.Targets {
		t := &target{
			host:      t.Addr,
			addresses: make([]net.IPAddr, 0),
			delay:     time.Duration(10*i) * time.Millisecond,
			resolver:  resolver,
		}
		targets[i] = t

		err := t.addOrUpdateMonitor(monitor, targetOpts{
			disableIPv4: cfg.Options.DisableIPv4,
			disableIPv6: cfg.Options.DisableIPv6,
		})
		if err != nil {
			Logger.Sugar().Error(zap.Error(err))
		}
	}

	go startDNSAutoRefresh(cfg.DNS.Refresh.Duration(), targets, monitor, cfg)

	return monitor, nil
}

func startDNSAutoRefresh(interval time.Duration, targets []*target, monitor *mon.Monitor, cfg *config.Config) {
	if interval <= 0 {
		return
	}

	for range time.NewTicker(interval).C {
		refreshDNS(targets, monitor, cfg)
	}
}

func refreshDNS(targets []*target, monitor *mon.Monitor, cfg *config.Config) {
	Logger.Sugar().Info("refreshing DNS")
	for _, t := range targets {
		go func(ta *target) {
			err := ta.addOrUpdateMonitor(monitor, targetOpts{
				disableIPv4: cfg.Options.DisableIPv4,
				disableIPv6: cfg.Options.DisableIPv6,
			})
			if err != nil {
				Logger.Error("could not refresh dns", zap.Error(err))
			}
		}(t)
	}
}

func printMetrics(cfg *config.Config, monitor *mon.Monitor) string {
	reg := prometheus.NewRegistry()
	reg.MustRegister(&pingCollector{
		monitor:      monitor,
		cfg:          cfg,
		customLabels: newCustomLabelSet(cfg.Targets),
	})
	// wait for metrics collected
	time.Sleep(10 * time.Second)
	g := prometheus.Gatherers{reg}
	gatheredMetrics, err := g.Gather()
	if err != nil {
		Logger.Fatal("", zap.Error(err))
	}

	buf := new(bytes.Buffer)
	for _, metric := range gatheredMetrics {
		_, err = expfmt.MetricFamilyToOpenMetrics(buf, metric)
		if err != nil {
			Logger.Fatal("", zap.Error(err))
		}
	}

	return (buf.String())

}

func setupResolver(cfg *config.Config) *net.Resolver {
	if cfg.DNS.Nameserver == "" {
		return net.DefaultResolver
	}

	if !strings.HasSuffix(cfg.DNS.Nameserver, ":53") {
		cfg.DNS.Nameserver += ":53"
	}
	dialer := func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, "udp", cfg.DNS.Nameserver)
	}

	return &net.Resolver{PreferGo: true, Dial: dialer}
}

func main() {

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
