package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/promptshield/promptshield/dashboard"
	"github.com/promptshield/promptshield/logger"
	"github.com/promptshield/promptshield/policy"
	"github.com/promptshield/promptshield/proxy"
	"github.com/promptshield/promptshield/scanner"
)

func main() {
	var (
		listenAddr        = flag.String("listen", "127.0.0.1:8080", "address the proxy listens on")
		upstream          = flag.String("upstream", "https://api.openai.com/v1", "upstream AI provider base URL")
		mode              = flag.String("mode", "block", "policy mode: block | redact | observe")
		auditPath         = flag.String("audit", "promptshield-audit.jsonl", "path to audit log file")
		authKey           = flag.String("auth-key", "", "optional shared secret clients must send")
		dashboardAddr     = flag.String("dashboard", "127.0.0.1:3000", "dashboard listen address (empty = disabled)")
		confirmBlocked    = flag.Bool("confirm", true, "ask before blocking: native popup, Yes = send it anyway, No/timeout = block")
		confirmTimeoutSec = flag.Int("confirm-timeout-sec", 60, "seconds to wait for the confirmation popup before auto-blocking")
	)
	flag.Parse()

	fmt.Println("==========================================")
	fmt.Println("  promptshield - AI Privacy Gateway")
	fmt.Println("==========================================")
	fmt.Printf("  Listening : %s\n", *listenAddr)
	fmt.Printf("  Upstream  : %s\n", *upstream)
	fmt.Printf("  Mode      : %s\n", *mode)
	if *dashboardAddr != "" {
		fmt.Printf("  Dashboard : http://%s\n", *dashboardAddr)
	}
	fmt.Println("------------------------------------------")
	fmt.Println("  Point your AI tool at http://localhost" + *listenAddr + "/v1")
	fmt.Println("==========================================")

	// Build components
	s := scanner.New()
	p := policy.Default()
	switch *mode {
	case "block":
		p.Mode = policy.ModeBlock
	case "redact":
		p.Mode = policy.ModeRedact
	case "observe":
		p.Mode = policy.ModeObserve
	default:
		log.Fatalf("unknown mode %q (use block, redact, observe)", *mode)
	}

	al, err := logger.New(*auditPath)
	if err != nil {
		log.Fatalf("failed to init audit log: %v", err)
	}

	cfg := proxy.Config{
		Upstream:       *upstream,
		ListenAddr:     *listenAddr,
		AuthKey:        *authKey,
		ConfirmBlocked: *confirmBlocked,
		ConfirmTimeout: time.Duration(*confirmTimeoutSec) * time.Second,
	}

	server := proxy.New(cfg, s, p, al)

	log.Printf("promptshield proxy ready on %s", *listenAddr)
	go func() {
		if err := http.ListenAndServe(*listenAddr, server.Handler()); err != nil {
			log.Fatalf("proxy server failed: %v", err)
		}
	}()

	if *dashboardAddr != "" {
		log.Printf("promptshield dashboard on %s", *dashboardAddr)
		go func() {
			if err := http.ListenAndServe(*dashboardAddr, dashboard.Handler(al)); err != nil {
				log.Fatalf("dashboard server failed: %v", err)
			}
		}()
	}

	// Block forever
	select {}
}