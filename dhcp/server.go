package dhcp

import (
	"dhcp/dhcp/v4"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

type Server struct {
	v4 *v4.DHCPv4
	//v6       dhcpv6

	mtu int
}

func NewServer(cfg *v4.Config) (*Server, error) {

	srv4, err := v4.MakeDHCPv4(cfg)
	if err != nil {
		return nil, err
	}

	s := &Server{
		v4: srv4,
	}

	return s, nil
}

func (s *Server) Run() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go s.run()

	select {
	case <-sig:
		slog.Info("Received signal, stopping server")
		s.close()
	}
	//slog.Info("waiting for all goroutines to finish")
	//
	//ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	//defer cancel()
	//
	//done := make(chan struct{})
	//go func() {
	//	s.wg.Wait()
	//	close(done)
	//}()
	//
	//select {
	//case <-done:
	//	slog.Info("All goroutines completed")
	//case <-ctx.Done():
	//	slog.Error("Timed out waiting for goroutines to complete")
	//}

	//slog.Info("Server stopped")
}

func (s *Server) run() {
	slog.Info("Starting server")
	slog.Info("Starting DHCPv4 server")
	s.v4.Start()
}

func (s *Server) close() {
	s.v4.Close()
}

//
//func runAsync(wg *sync.WaitGroup, f func()) {
//	wg.Add(1)
//	go func() {
//		defer wg.Done()
//		f()
//	}()
//}
