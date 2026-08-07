package quicconfig

import "testing"

func TestPerformanceAndEarlyDataSettings(t *testing.T) {
	client := Client()
	server := Server()
	for name, config := range map[string]struct {
		stream uint64
		conn   uint64
	}{
		"client": {client.InitialStreamReceiveWindow, client.InitialConnectionReceiveWindow},
		"server": {server.InitialStreamReceiveWindow, server.InitialConnectionReceiveWindow},
	} {
		if config.stream != InitialStreamWindow || config.conn != InitialConnectionWindow {
			t.Fatalf("%s receive windows = %d/%d", name, config.stream, config.conn)
		}
	}
	if client.Allow0RTT {
		t.Fatal("client must not accept inbound 0-RTT")
	}
	if !server.Allow0RTT {
		t.Fatal("server does not allow 0-RTT")
	}
	if !client.EnableDatagrams || !server.EnableDatagrams {
		t.Fatal("QUIC datagrams are disabled")
	}
}
