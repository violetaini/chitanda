package client

import (
	"context"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

type h2Prober struct {
	client       *Client
	h2Degraded   atomic.Bool
	ctx          context.Context
	cancel       context.CancelFunc
}

func newH2Prober(c *Client) *h2Prober {
	ctx, cancel := context.WithCancel(context.Background())
	p := &h2Prober{
		client: c,
		ctx:    ctx,
		cancel: cancel,
	}
	go p.loop()
	return p
}

func (p *h2Prober) loop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	
	consecutiveFails := 0
	consecutiveSuccesses := 0

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			rtt, err := p.pingH2()
			if err != nil || rtt > 500*time.Millisecond {
				consecutiveFails++
				consecutiveSuccesses = 0
				if consecutiveFails >= 2 && !p.h2Degraded.Load() {
					log.Printf("myxray client: H2 degraded (err: %v, rtt: %v), failing over TCP to H3", err, rtt)
					p.h2Degraded.Store(true)
				}
			} else {
				consecutiveSuccesses++
				consecutiveFails = 0
				if consecutiveSuccesses >= 10 && p.h2Degraded.Load() {
					log.Printf("myxray client: H2 recovered (rtt: %v), restoring TCP to H2", rtt)
					p.h2Degraded.Store(false)
				}
			}
		}
	}
}

func (p *h2Prober) pingH2() (time.Duration, error) {
	h2Cli := p.client.pickBestH2Client()
	if h2Cli == nil {
		return 0, io.EOF
	}
	req, err := http.NewRequestWithContext(p.ctx, http.MethodHead, p.client.rootURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Carrier-Probe", "1")
	start := time.Now()
	resp, err := h2Cli.transport.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return time.Since(start), nil
}

func (p *h2Prober) Close() {
	p.cancel()
}

