// Package webhook — server.go
// HTTPS 서버로 Admission Webhook을 서빙한다.
package webhook

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Server runs the admission webhook HTTPS server.
type Server struct {
	handler  *Handler
	port     int
	certDir  string
	server   *http.Server
}

// NewServer creates a webhook server.
func NewServer(handler *Handler, port int, certDir string) *Server {
	return &Server{
		handler: handler,
		port:    port,
		certDir: certDir,
	}
}

// Start begins serving the webhook. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/validate-pod", s.handler.HandleValidate)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	certFile := filepath.Join(s.certDir, "tls.crt")
	keyFile := filepath.Join(s.certDir, "tls.key")

	// TLS 인증서가 없으면 HTTP로 시작 (개발용)
	useTLS := fileExists(certFile) && fileExists(keyFile)

	addr := fmt.Sprintf(":%d", s.port)
	s.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if useTLS {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("load webhook TLS cert: %w", err)
		}
		s.server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		log.Printf("webhook server starting on %s (TLS)", addr)
	} else {
		log.Printf("webhook server starting on %s (plaintext, dev mode — no TLS certs found in %s)", addr, s.certDir)
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			log.Printf("webhook server shutdown error: %v", err)
		}
	}()

	var err error
	if useTLS {
		err = s.server.ListenAndServeTLS("", "")
	} else {
		err = s.server.ListenAndServe()
	}

	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
