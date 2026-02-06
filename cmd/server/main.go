package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type addArgs struct {
	A int `json:"a" jsonschema:"description=First integer"`
	B int `json:"b" jsonschema:"description=Second integer"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	host := getenv("HOST", "127.0.0.1")
	port := getenv("PORT", "8000")
	addr := fmt.Sprintf("%s:%s", host, port)

	allowOrigins := parseCSVEnv("MCP_CORS_ALLOW_ORIGINS", []string{"http://localhost:3000", "http://127.0.0.1:3000"})
	allowCredentials := parseBoolEnv("MCP_CORS_ALLOW_CREDENTIALS", false)
	maxBodyBytes := parseIntEnv("MCP_MAX_BODY_BYTES", 256*1024)
	authToken := strings.TrimSpace(os.Getenv("MCP_AUTH_TOKEN"))

	// MCP server (streamable HTTP).
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "mcp-secure-go-starter",
		Version: "0.1.0",
	}, nil)

	// Minimal safe tool surface area by default.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "add",
		Description: "Add two integers.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args addArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("%d", args.A+args.B)},
			},
		}, nil, nil
	})

	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return server
	}, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.Handle("/", mcpHandler)

	// Wrap with security middlewares.
	handler := withCORS(mux, corsConfig{
		allowOrigins:     allowOrigins,
		allowCredentials: allowCredentials,
	})
	handler = withOptionalBearerAuth(handler, authToken, map[string]bool{"/healthz": true})
	handler = withMaxBodyBytes(handler, int64(maxBodyBytes))

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("MCP server listening on http://%s", addr)

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server failed: %v", err)
	}
}

type corsConfig struct {
	allowOrigins     map[string]bool
	allowCredentials bool
}

func withCORS(next http.Handler, cfg corsConfig) http.Handler {
	const exposeHeaders = "Mcp-Session-Id"
	const allowMethods = "GET, POST, DELETE, OPTIONS"
	const allowHeaders = "Authorization, Content-Type, Mcp-Session-Id"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && cfg.allowOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			if cfg.allowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.Header().Set("Access-Control-Allow-Methods", allowMethods)
			w.Header().Set("Access-Control-Allow-Headers", allowHeaders)
			w.Header().Set("Access-Control-Expose-Headers", exposeHeaders)
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func withMaxBodyBytes(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}

func withOptionalBearerAuth(next http.Handler, token string, exempt map[string]bool) http.Handler {
	if token == "" {
		return next
	}

	expected := "Bearer " + token

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if exempt[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		if r.Header.Get("Authorization") != expected {
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"detail":"Unauthorized"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func getenv(name, def string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	return v
}

func parseCSVEnv(name string, defaults []string) map[string]bool {
	raw := os.Getenv(name)
	var vals []string
	if strings.TrimSpace(raw) == "" {
		vals = defaults
	} else {
		parts := strings.Split(raw, ",")
		for _, p := range parts {
			s := strings.TrimSpace(p)
			if s != "" {
				vals = append(vals, s)
			}
		}
	}

	out := make(map[string]bool, len(vals))
	for _, v := range vals {
		out[v] = true
	}
	return out
}

func parseBoolEnv(name string, def bool) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func parseIntEnv(name string, def int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

