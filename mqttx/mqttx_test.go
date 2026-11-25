package mqttx

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// message is one PUBLISH the fake broker received.
type message struct {
	topic   string
	payload string
	retain  bool
}

// connectPacket is what the fake broker read from a CONNECT.
type connectPacket struct {
	clientID, username, password string
	willTopic, willPayload       string
	willRetain                   bool
}

// broker is a minimal MQTT 3.1.1 server on loopback: enough of CONNECT, PUBLISH (QoS 0 and 1),
// SUBSCRIBE, PINGREQ and DISCONNECT to exercise the client.
type broker struct {
	t        *testing.T
	listener net.Listener

	mu        sync.Mutex
	connects  []connectPacket
	published []message
	filters   []string
	conns     []net.Conn
}

func newBroker(t *testing.T) *broker {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b := &broker{t: t, listener: listener}
	go b.accept()
	t.Cleanup(func() {
		_ = listener.Close()
		b.drop()
	})
	return b
}

func (b *broker) url() string { return "tcp://" + b.listener.Addr().String() }

func (b *broker) accept() {
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			return
		}
		b.mu.Lock()
		b.conns = append(b.conns, conn)
		b.mu.Unlock()
		go b.serve(conn)
	}
}

// drop closes every connection, as a broker restart would.
func (b *broker) drop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, conn := range b.conns {
		_ = conn.Close()
	}
	b.conns = nil
}

func readString(data []byte) (string, []byte) {
	if len(data) < 2 {
		return "", nil
	}
	n := int(binary.BigEndian.Uint16(data))
	if len(data) < 2+n {
		return "", nil
	}
	return string(data[2 : 2+n]), data[2+n:]
}

func appendString(out []byte, text string) []byte {
	out = binary.BigEndian.AppendUint16(out, uint16(len(text)))
	return append(out, text...)
}

func remaining(n int) []byte {
	var out []byte
	for {
		digit := byte(n % 128)
		n /= 128
		if n > 0 {
			digit |= 0x80
		}
		out = append(out, digit)
		if n == 0 {
			return out
		}
	}
}

func (b *broker) serve(conn net.Conn) {
	reader := bufio.NewReader(conn)
	for {
		header, err := reader.ReadByte()
		if err != nil {
			return
		}
		length, multiplier := 0, 1
		for {
			digit, err := reader.ReadByte()
			if err != nil {
				return
			}
			length += int(digit&0x7f) * multiplier
			multiplier *= 128
			if digit&0x80 == 0 {
				break
			}
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(reader, body); err != nil {
			return
		}
		var reply []byte
		switch header >> 4 {
		case 1: // CONNECT
			b.connect(body)
			reply = []byte{0x20, 0x02, 0x00, 0x00}
		case 3: // PUBLISH
			qos := (header >> 1) & 0x03
			topic, rest := readString(body)
			var id []byte
			if qos > 0 {
				id, rest = rest[:2], rest[2:]
				reply = append([]byte{0x40, 0x02}, id...)
			}
			b.mu.Lock()
			b.published = append(b.published, message{topic: topic, payload: string(rest), retain: header&0x01 == 1})
			b.mu.Unlock()
		case 8: // SUBSCRIBE
			id, rest := body[:2], body[2:]
			var granted []byte
			for len(rest) > 0 {
				var filter string
				filter, rest = readString(rest)
				rest = rest[1:]
				granted = append(granted, 0x01)
				b.mu.Lock()
				b.filters = append(b.filters, filter)
				b.mu.Unlock()
			}
			reply = append(append([]byte{0x90}, remaining(2+len(granted))...), append(id, granted...)...)
		case 12: // PINGREQ
			reply = []byte{0xd0, 0x00}
		case 14: // DISCONNECT
			_ = conn.Close()
			return
		}
		if reply != nil {
			if _, err := conn.Write(reply); err != nil {
				return
			}
		}
	}
}

func (b *broker) connect(body []byte) {
	_, rest := readString(body) // protocol name
	flags := rest[1]
	rest = rest[4:] // level, flags, keep alive
	var packet connectPacket
	packet.clientID, rest = readString(rest)
	if flags&0x04 != 0 {
		packet.willTopic, rest = readString(rest)
		packet.willPayload, rest = readString(rest)
		packet.willRetain = flags&0x20 != 0
	}
	if flags&0x80 != 0 {
		packet.username, rest = readString(rest)
	}
	if flags&0x40 != 0 {
		packet.password, _ = readString(rest)
	}
	b.mu.Lock()
	b.connects = append(b.connects, packet)
	b.mu.Unlock()
}

// send pushes a QoS 0 PUBLISH to every connected client.
func (b *broker) send(topic, payload string) {
	packet := appendString(nil, topic)
	packet = append(packet, payload...)
	frame := append(append([]byte{0x30}, remaining(len(packet))...), packet...)
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, conn := range b.conns {
		_, _ = conn.Write(frame)
	}
}

func (b *broker) snapshot() ([]connectPacket, []message, []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]connectPacket(nil), b.connects...), append([]message(nil), b.published...), append([]string(nil), b.filters...)
}

func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newClient(t *testing.T, b *broker) *Client {
	t.Helper()
	client := New(Options{
		Broker: b.url(), ClientID: "test-service", Username: "user", Password: "pass",
		AvailabilityTopic: "test-service/availability", Timeout: 2 * time.Second,
	})
	t.Cleanup(client.Close)
	return client
}

func TestConnectMarksTheServiceAvailableWithAWill(t *testing.T) {
	b := newBroker(t)
	client := newClient(t, b)
	var connected atomic.Int32
	client.OnConnect(func(context.Context) { connected.Add(1) })
	if err := client.Connect(t.Context()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	eventually(t, "the availability and the connect handler", func() bool {
		_, published, _ := b.snapshot()
		return len(published) > 0 && connected.Load() == 1
	})
	connects, published, _ := b.snapshot()
	want := connectPacket{clientID: "test-service", username: "user", password: "pass",
		willTopic: "test-service/availability", willPayload: "offline", willRetain: true}
	if connects[0] != want {
		t.Fatalf("CONNECT = %+v, want %+v", connects[0], want)
	}
	if published[0] != (message{topic: "test-service/availability", payload: "online", retain: true}) {
		t.Fatalf("first message = %+v, want the retained online availability", published[0])
	}
}

func TestPublishWaitsForTheBrokerAndRefusesWithoutAConnection(t *testing.T) {
	b := newBroker(t)
	client := newClient(t, b)
	if err := client.Publish(t.Context(), "test-service/state", []byte("{}"), true); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Publish before Connect = %v, want ErrNotConnected", err)
	}
	if err := client.Connect(t.Context()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	// The connect handler marks the service online on its own goroutine; let it finish first.
	eventually(t, "the availability", func() bool { _, published, _ := b.snapshot(); return len(published) == 1 })
	if err := client.Publish(t.Context(), "test-service/state", []byte(`{"due":3}`), true); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	_, published, _ := b.snapshot()
	if last := published[len(published)-1]; last != (message{topic: "test-service/state", payload: `{"due":3}`, retain: true}) {
		t.Fatalf("last message = %+v", last)
	}
	client.Close()
	_, published, _ = b.snapshot()
	if last := published[len(published)-1]; last != (message{topic: "test-service/availability", payload: "offline", retain: true}) {
		t.Fatalf("Close published %+v, want the retained offline availability", last)
	}
}

func TestAReconnectRenewsAvailabilitySubscriptionsAndReplays(t *testing.T) {
	b := newBroker(t)
	client := newClient(t, b)
	var connected atomic.Int32
	client.OnConnect(func(context.Context) { connected.Add(1) })
	if err := client.Connect(t.Context()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	eventually(t, "the first connect handler", func() bool { return connected.Load() == 1 })
	if err := client.Subscribe(t.Context(), "homeassistant/status", func(string, []byte) {}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	b.drop()
	eventually(t, "the reconnect", func() bool {
		connects, _, filters := b.snapshot()
		return len(connects) >= 2 && len(filters) >= 2 && connected.Load() >= 2 && filters[len(filters)-1] == "homeassistant/status"
	})
	_, published, filters := b.snapshot()
	online := 0
	for _, m := range published {
		if m.topic == "test-service/availability" && m.payload == "online" {
			online++
		}
	}
	// Every connection marks the service online and subscribes again; paho may reconnect more
	// than once while the broker drops it.
	if online < 2 || filters[len(filters)-1] != "homeassistant/status" {
		t.Fatalf("after the reconnect: %d online messages, filters %v", online, filters)
	}
}

func TestABirthIsAnsweredOnceAfterTheDelay(t *testing.T) {
	b := newBroker(t)
	client := newClient(t, b)
	if err := client.Connect(t.Context()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	eventually(t, "the availability", func() bool { _, published, _ := b.snapshot(); return len(published) == 1 })
	var replays atomic.Int32
	if err := client.watchBirth(t.Context(), "homeassistant/status", "online", func(context.Context) { replays.Add(1) },
		func() time.Duration { return 200 * time.Millisecond }); err != nil {
		t.Fatalf("watchBirth: %v", err)
	}
	eventually(t, "the subscription", func() bool { _, _, filters := b.snapshot(); return len(filters) >= 1 })
	b.send("homeassistant/status", "offline")
	b.send("homeassistant/status", "online")
	b.send("homeassistant/status", "online")
	eventually(t, "the replay", func() bool { return replays.Load() == 1 })
	time.Sleep(400 * time.Millisecond)
	if n := replays.Load(); n != 1 {
		t.Fatalf("two births in one wait gave %d replays, want 1", n)
	}
	if err := client.WatchBirth(t.Context(), "test-service/availability", "online", func(context.Context) {}); err == nil {
		t.Fatal("WatchBirth accepted the availability topic as the status topic")
	}
}

// A connect handler gets a context that Close cancels, so a handler still publishing at
// shutdown stops instead of outliving the client.
func TestCloseCancelsTheConnectHandlers(t *testing.T) {
	b := newBroker(t)
	client := newClient(t, b)
	var started, stopped atomic.Bool
	client.OnConnect(func(ctx context.Context) {
		started.Store(true)
		<-ctx.Done()
		stopped.Store(true)
	})
	if err := client.Connect(t.Context()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	eventually(t, "the connect handler", started.Load)
	client.Close()
	eventually(t, "the handler to see the cancellation", stopped.Load)
}

// A service that must not show stale values as live marks itself online once it has a good state;
// the last will and Close still mark it offline.
func TestDeferOnlineLeavesTheOnlineMessageToTheCaller(t *testing.T) {
	b := newBroker(t)
	client := New(Options{
		Broker: b.url(), ClientID: "test-service", AvailabilityTopic: "test-service/availability",
		DeferOnline: true, Timeout: 2 * time.Second,
	})
	t.Cleanup(client.Close)
	var connected atomic.Int32
	client.OnConnect(func(context.Context) { connected.Add(1) })
	if err := client.Connect(t.Context()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	eventually(t, "the connect handler", func() bool { return connected.Load() == 1 })
	connects, published, _ := b.snapshot()
	if connects[0].willTopic != "test-service/availability" || connects[0].willPayload != "offline" {
		t.Fatalf("CONNECT = %+v, want the offline will", connects[0])
	}
	if len(published) != 0 {
		t.Fatalf("published %+v before the caller marked the service online", published)
	}

	if err := client.SetAvailability(t.Context(), true); err != nil {
		t.Fatalf("SetAvailability: %v", err)
	}
	b.drop()
	eventually(t, "the reconnect", func() bool { return connected.Load() == 2 })
	_, published, _ = b.snapshot()
	if len(published) != 1 || published[0] != (message{topic: "test-service/availability", payload: "online", retain: true}) {
		t.Fatalf("published %+v, want only the caller's retained online message", published)
	}
	client.Close()
	_, published, _ = b.snapshot()
	if last := published[len(published)-1]; last.payload != "offline" || !last.retain {
		t.Fatalf("Close published %+v, want the retained offline availability", last)
	}
}

// A connect that lands while Close runs must not mark the service online after Close marked it
// offline: the clean disconnect that follows would leave the retained "online" in place.
func TestAConnectDuringClosePublishesNothing(t *testing.T) {
	b := newBroker(t)
	client := newClient(t, b)
	if err := client.Connect(t.Context()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	eventually(t, "the availability", func() bool { _, published, _ := b.snapshot(); return len(published) == 1 })
	client.cancel() // Close has begun
	client.onConnect(client.client)
	if _, published, _ := b.snapshot(); len(published) != 1 {
		t.Fatalf("published %+v after Close began", published[1:])
	}
}
