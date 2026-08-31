package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// NewFallback creates a fallback handler based on the target configuration.
func NewFallback(target, serverName string) (http.Handler, error) {
	target = strings.TrimSpace(target)
	if target == "" || target == "embed" || target == "default" {
		return newERPFallbackHandler(serverName), nil
	}

	// Check if local directory exists
	if stat, err := os.Stat(target); err == nil && stat.IsDir() {
		return http.FileServer(http.Dir(target)), nil
	}

	// Check Unix Domain Socket (e.g. unix:/run/nginx.sock)
	if strings.HasPrefix(target, "unix:") {
		socketPath := strings.TrimPrefix(target, "unix:")
		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = "http"
				req.URL.Host = "localhost"
				if serverName != "" {
					req.Host = serverName
				}
			},
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var dialer net.Dialer
					return dialer.DialContext(ctx, "unix", socketPath)
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
			ModifyResponse: sanitizeFallbackResponse,
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
				http.NotFound(w, nil)
			},
		}
		return proxy, nil
	}

	// Local host/port or remote URL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid fallback target: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = &http.Transport{
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	proxy.ModifyResponse = sanitizeFallbackResponse
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.NotFound(w, nil)
	}
	return proxy, nil
}

func sanitizeFallbackResponse(response *http.Response) error {
	response.Header.Del(headerSessionOK)
	response.Header.Del(headerFraming)
	response.Header.Del("X-Session-Early")
	return nil
}

func (s *Server) serveFallback(w http.ResponseWriter, r *http.Request) {
	privateAttempt := false
	for _, name := range []string{headerTarget, headerTimestamp, headerNonce, headerSignature, headerMode} {
		if _, present := r.Header[http.CanonicalHeaderKey(name)]; present {
			privateAttempt = true
		}
		r.Header.Del(name)
	}
	if privateAttempt {
		if r.ProtoMajor == 1 {
			w.Header().Set("Connection", "close")
			defer func() {
				_ = http.NewResponseController(w).SetReadDeadline(time.Unix(1, 0))
			}()
		}
		r.Body = http.NoBody
		r.GetBody = nil
		r.ContentLength = 0
		r.TransferEncoding = nil
		r.Trailer = nil
		r.Header.Del("Content-Length")
		r.Header.Del("Transfer-Encoding")
		r.Header.Del("Expect")
	}
	s.fallback.ServeHTTP(w, r)
}

type erpFallbackHandler struct {
	serverName string
	tmpl       *template.Template
}

func newERPFallbackHandler(serverName string) http.Handler {
	tmpl := template.Must(template.New("erp").Parse(erpHtmlTemplate))
	return &erpFallbackHandler{
		serverName: serverName,
		tmpl:       tmpl,
	}
}

type erpPageData struct {
	ServerName    string
	ClusterID     string
	TraceID       string
	RequestSyncID string
	Timestamp     string
}

func (h *erpFallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	randomBytes := make([]byte, 8)
	_, _ = rand.Read(randomBytes)
	traceID := "vg-trace-" + hex.EncodeToString(randomBytes)

	syncBytes := make([]byte, 4)
	_, _ = rand.Read(syncBytes)
	syncID := strings.ToUpper(hex.EncodeToString(syncBytes))

	clusterNum := (int(randomBytes[0]) % 8) + 1
	clusterID := fmt.Sprintf("vg-cluster-prod-0%d", clusterNum)

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") || strings.HasPrefix(r.URL.Path, "/api") || strings.HasPrefix(r.URL.Path, "/v1") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":         200,
			"status":       "UP",
			"organization": "Vanguard Global Industrial Group, Ltd.",
			"service":      "Enterprise Operations & SCM Microservices Gateway (VG-ERP-Core)",
			"vendor":       "SoftLink Information Systems Corp.",
			"version":      "4.22.0-RELEASE",
			"cluster":      clusterID,
			"trace_id":     traceID,
			"timestamp":    time.Now().Unix(),
			"path":         r.URL.Path,
		})
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	data := erpPageData{
		ServerName:    h.serverName,
		ClusterID:     clusterID,
		TraceID:       traceID,
		RequestSyncID: syncID,
		Timestamp:     time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
	}
	_ = h.tmpl.Execute(w, data)
}

const erpHtmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vanguard Global - Enterprise Resource & SCM Operations Gateway</title>
    <style>
        :root {
            --primary: #1e3a8a;
            --primary-light: #2563eb;
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --success: #10b981;
            --success-bg: rgba(16, 185, 129, 0.12);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            padding: 36px 16px;
        }
        .container { max-width: 820px; margin: 0 auto; width: 100%; }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 32px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
        }
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 24px;
        }
        .brand { display: flex; align-items: center; gap: 14px; }
        .logo-icon {
            width: 42px;
            height: 42px;
            background: linear-gradient(135deg, var(--primary), var(--primary-light));
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            color: #fff;
            font-size: 16px;
            letter-spacing: 0.5px;
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
        }
        .title { font-size: 19px; font-weight: 600; color: #ffffff; }
        .subtitle { font-size: 13px; color: var(--text-muted); margin-top: 3px; }
        .badge {
            background: var(--success-bg);
            color: var(--success);
            border: 1px solid rgba(16, 185, 129, 0.2);
            padding: 6px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 500;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .badge-dot { width: 6px; height: 6px; background: var(--success); border-radius: 50%; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .stat-box {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }
        .stat-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
        .stat-val { font-size: 14px; font-weight: 600; color: #38bdf8; margin-top: 6px; word-break: break-all; }
        .section-title { font-size: 13px; font-weight: 600; color: var(--text-muted); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
        .modules-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 10px;
            margin-bottom: 24px;
        }
        .module-item {
            background: rgba(15, 23, 42, 0.4);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 10px 12px;
            font-size: 13px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .module-status { font-size: 11px; color: var(--success); }
        .notice {
            background: rgba(37, 99, 235, 0.08);
            border-left: 3px solid var(--primary-light);
            padding: 14px 16px;
            border-radius: 0 6px 6px 0;
            font-size: 12px;
            color: #cbd5e1;
            line-height: 1.6;
        }
        .footer {
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 24px;
            line-height: 1.8;
        }
        .footer a { color: var(--text-muted); text-decoration: none; }
        .footer-vendor { color: #64748b; font-size: 11px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <div class="brand">
                    <div class="logo-icon">VG</div>
                    <div>
                        <div class="title">Vanguard Global Industrial &bull; Operations Hub</div>
                        <div class="subtitle">Enterprise Resource Planning & SCM Gateway v4.2</div>
                    </div>
                </div>
                <div class="badge">
                    <div class="badge-dot"></div>
                    <span>Cluster Operational</span>
                </div>
            </div>

            <div class="grid">
                <div class="stat-box">
                    <div class="stat-label">Service Status</div>
                    <div class="stat-val">RUNNING (STANDBY-READY)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Access Protocol</div>
                    <div class="stat-val">mTLS 1.3 / OAuth 2.0 PKCE</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Production Cluster Node</div>
                    <div class="stat-val">{{.ClusterID}}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Audit Trace ID</div>
                    <div class="stat-val">{{.TraceID}}</div>
                </div>
            </div>

            <div class="section-title">Core Subsystem Status</div>
            <div class="modules-list">
                <div class="module-item">
                    <span>SCM Supply Chain Engine</span>
                    <span class="module-status">&bull; Operational</span>
                </div>
                <div class="module-item">
                    <span>CRM & Client Portal</span>
                    <span class="module-status">&bull; Operational</span>
                </div>
                <div class="module-item">
                    <span>FIN General Ledger</span>
                    <span class="module-status">&bull; Operational</span>
                </div>
                <div class="module-item">
                    <span>WMS Smart Warehousing</span>
                    <span class="module-status">&bull; Operational</span>
                </div>
            </div>

            <div class="notice">
                <strong>Corporate Security Policy</strong>: This access gateway serves as an internal API endpoint for Vanguard Global production services. Access is restricted to authorized corporate networks and authenticated microservices with valid TLS client credentials or access tokens. Unauthorized requests are logged and rejected.
            </div>
        </div>

        <div class="footer">
            <div>&copy; 2024-2026 Vanguard Global Industrial Group, Ltd. All rights reserved.</div>
            <div class="footer-vendor">Infrastructure & Systems Management powered by <strong>SoftLink Information Systems Corp.</strong> &bull; Node Sync ID: {{.RequestSyncID}}</div>
        </div>
    </div>
</body>
</html>
`

type flushWriter struct {
	w http.ResponseWriter
}

func (w flushWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if flusher, ok := w.w.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}
