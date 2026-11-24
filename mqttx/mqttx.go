// Package mqttx is an MQTT client for services that publish to a broker, typically for Home
// Assistant: it keeps the connection up, marks the service available through a retained status
// topic with a last will, and replays what the service publishes when the connection comes back
// or when Home Assistant restarts.
//
// The package composes no topic and no payload: the availability topic, its payloads and the Home
// Assistant status topic are the caller's. It uses the Eclipse Paho client; publishing is QoS 1. A
// message in flight when the connection drops is not sent again on the next connection: the
// OnConnect handlers publish the current state, which is what a publishing service needs.
//
//	client := mqttx.New(mqttx.Options{
//		Broker: "tcp://broker.example.com:1883", ClientID: "my-service",
//		AvailabilityTopic: "my-service/availability",
//	})
//	client.OnConnect(func(ctx context.Context) { publishDiscoveryAndState(ctx, client) })
//	client.ConnectAsync(ctx)
//	defer client.Close()
package mqttx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
	"github.com/eclipse/paho.mqtt.golang/packets"
)

// Default payloads of the availability topic, the ones Home Assistant expects unless told otherwise.
const (
	DefaultOnlinePayload  = "online"
	DefaultOfflinePayload = "offline"
)

// ErrNotConnected means a publish was attempted while the client has no connection.
var ErrNotConnected = errors.New("mqtt: not connected")

// Options configure a Client.
type Options struct {
	// Broker is the broker's address: tcp://host:1883, ssl://host:8883 or ws://host/path.
	Broker   string
	Username string
	Password string
	// ClientID identifies the connection to the broker; two clients with one ID displace each other.
	ClientID string
	// AvailabilityTopic receives OnlinePayload (retained) on every connect and OfflinePayload as
	// the last will and on Close. Empty publishes no availability.
	AvailabilityTopic string
	// OnlinePayload and OfflinePayload default to "online" and "offline".
	OnlinePayload  string
	OfflinePayload string
	// Timeout bounds one publish or subscribe; zero means 5 seconds.
	Timeout time.Duration
	// Logger receives connection events; nil discards them.
	Logger *slog.Logger
}

// Client is a connection to one broker. It is safe for concurrent use.
type Client struct {
	opts   Options
	client paho.Client

	mu            sync.Mutex
	connectFns    []func(context.Context)
	subscriptions map[string]func(topic string, payload []byte)
}

// New returns a client; nothing connects until Connect or ConnectAsync.
func New(opts Options) *Client {
	opts.Broker = strings.TrimSpace(opts.Broker)
	if opts.OnlinePayload == "" {
		opts.OnlinePayload = DefaultOnlinePayload
	}
	if opts.OfflinePayload == "" {
		opts.OfflinePayload = DefaultOfflinePayload
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	c := &Client{opts: opts, subscriptions: map[string]func(string, []byte){}}
	c.client = paho.NewClient(c.clientOptions())
	return c
}

func (c *Client) clientOptions() *paho.ClientOptions {
	options := paho.NewClientOptions()
	options.AddBroker(c.opts.Broker)
	options.SetClientID(c.opts.ClientID)
	options.SetUsername(c.opts.Username)
	options.SetPassword(c.opts.Password)
	options.SetAutoReconnect(true)
	options.SetConnectRetry(true)
	options.SetCleanSession(true)
	options.SetKeepAlive(30 * time.Second)
	options.SetPingTimeout(10 * time.Second)
	options.SetMaxReconnectInterval(time.Minute)
	// Nothing in flight is kept for a resend after a reconnect (see the package comment); Paho's
	// resend path also races with its writer.
	options.SetStore(forgetfulStore{})
	if c.opts.AvailabilityTopic != "" {
		options.SetWill(c.opts.AvailabilityTopic, c.opts.OfflinePayload, 1, true)
	}
	options.SetOnConnectHandler(c.onConnect)
	options.SetConnectionLostHandler(func(_ paho.Client, err error) {
		c.opts.Logger.Warn("mqtt connection lost", "error", err)
	})
	return options
}

// onConnect runs on every connection, the first and each reconnect: availability, the
// subscriptions again (the session is clean), then the caller's handlers.
func (c *Client) onConnect(client paho.Client) {
	c.opts.Logger.Info("mqtt connected")
	if c.opts.AvailabilityTopic != "" {
		token := client.Publish(c.opts.AvailabilityTopic, 1, true, c.opts.OnlinePayload)
		if !token.WaitTimeout(c.opts.Timeout) || token.Error() != nil {
			c.opts.Logger.Warn("mqtt availability not published", "error", token.Error())
		}
	}
	c.mu.Lock()
	subscriptions := make(map[string]func(string, []byte), len(c.subscriptions))
	for topic, handler := range c.subscriptions {
		subscriptions[topic] = handler
	}
	handlers := append([]func(context.Context){}, c.connectFns...)
	c.mu.Unlock()
	for topic, handler := range subscriptions {
		token := client.Subscribe(topic, 1, wrap(handler))
		if !token.WaitTimeout(c.opts.Timeout) || token.Error() != nil {
			c.opts.Logger.Warn("mqtt subscription failed", "topic", topic, "error", token.Error())
		}
	}
	for _, handler := range handlers {
		go handler(context.Background())
	}
}

// forgetfulStore is a paho.Store that keeps nothing.
type forgetfulStore struct{}

func (forgetfulStore) Open()                             {}
func (forgetfulStore) Put(string, packets.ControlPacket) {}
func (forgetfulStore) Get(string) packets.ControlPacket  { return nil }
func (forgetfulStore) All() []string                     { return nil }
func (forgetfulStore) Del(string)                        {}
func (forgetfulStore) Close()                            {}
func (forgetfulStore) Reset()                            {}

func wrap(handler func(topic string, payload []byte)) paho.MessageHandler {
	return func(_ paho.Client, message paho.Message) {
		handler(message.Topic(), message.Payload())
	}
}

// OnConnect registers fn to run (on its own goroutine) after every connection, the first and each
// reconnect: the place to publish discovery and the current state, which a clean session lost.
// Register handlers before connecting.
func (c *Client) OnConnect(fn func(ctx context.Context)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connectFns = append(c.connectFns, fn)
}

// Connect connects and waits for the first connection, at most until ctx ends.
func (c *Client) Connect(ctx context.Context) error {
	return c.wait(ctx, c.client.Connect(), 0)
}

// ConnectAsync starts connecting and returns at once; the client keeps retrying in the background
// until the broker answers, so a service can start before its broker.
func (c *Client) ConnectAsync(ctx context.Context) {
	token := c.client.Connect()
	go func() {
		<-token.Done()
		if err := token.Error(); err != nil && ctx.Err() == nil {
			c.opts.Logger.Warn("mqtt connect failed", "error", err)
		}
	}()
}

// IsConnected reports whether the connection is up now.
func (c *Client) IsConnected() bool {
	return c.client.IsConnectionOpen()
}

// Publish sends payload to topic with QoS 1 and waits for the broker's acknowledgement.
func (c *Client) Publish(ctx context.Context, topic string, payload []byte, retain bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !c.client.IsConnectionOpen() {
		return fmt.Errorf("publish %s: %w", topic, ErrNotConnected)
	}
	if err := c.wait(ctx, c.client.Publish(topic, 1, retain, payload), c.opts.Timeout); err != nil {
		return fmt.Errorf("publish %s: %w", topic, err)
	}
	return nil
}

// Subscribe receives the messages of topic (a filter may use + and #) with handler, now and after
// every reconnect. The handler runs on the client's goroutine and must return quickly.
func (c *Client) Subscribe(ctx context.Context, topic string, handler func(topic string, payload []byte)) error {
	c.mu.Lock()
	c.subscriptions[topic] = handler
	c.mu.Unlock()
	if !c.client.IsConnectionOpen() {
		return nil // subscribed on the next connect
	}
	if err := c.wait(ctx, c.client.Subscribe(topic, 1, wrap(handler)), c.opts.Timeout); err != nil {
		return fmt.Errorf("subscribe %s: %w", topic, err)
	}
	return nil
}

// WatchBirth calls replay when Home Assistant announces it is online on statusTopic (its
// "homeassistant/status" birth message with onlinePayload): Home Assistant forgets entities whose
// retained discovery it did not get, for example when the broker dropped them. The replay waits a
// random 2 to 5 seconds, so many services do not answer the same birth at once, and births during
// the wait are served by one replay. It stops when ctx ends.
func (c *Client) WatchBirth(ctx context.Context, statusTopic, onlinePayload string, replay func(context.Context)) error {
	return c.watchBirth(ctx, statusTopic, onlinePayload, replay, func() time.Duration {
		return 2*time.Second + rand.N(3*time.Second) //nolint:gosec // G404: spreading replays needs no secret randomness
	})
}

func (c *Client) watchBirth(ctx context.Context, statusTopic, onlinePayload string, replay func(context.Context),
	delay func() time.Duration) error {
	if statusTopic == "" || replay == nil {
		return errors.New("mqtt: WatchBirth needs a status topic and a replay function")
	}
	if statusTopic == c.opts.AvailabilityTopic {
		return errors.New("mqtt: the Home Assistant status topic must differ from the availability topic")
	}
	births := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-births:
			}
			timer := time.NewTimer(delay())
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			select { // a birth during the wait is answered by this replay
			case <-births:
			default:
			}
			replay(ctx)
		}
	}()
	return c.Subscribe(ctx, statusTopic, func(_ string, payload []byte) {
		if string(payload) != onlinePayload {
			return
		}
		select {
		case births <- struct{}{}:
		default:
		}
	})
}

// Close marks the service offline, when connected, and disconnects.
func (c *Client) Close() {
	if c.opts.AvailabilityTopic != "" && c.client.IsConnectionOpen() {
		ctx, cancel := context.WithTimeout(context.Background(), c.opts.Timeout)
		_ = c.Publish(ctx, c.opts.AvailabilityTopic, []byte(c.opts.OfflinePayload), true)
		cancel()
	}
	c.client.Disconnect(250)
}

// wait waits for a token, ctx, and a timeout (none when zero).
func (c *Client) wait(ctx context.Context, token paho.Token, timeout time.Duration) error {
	var expired <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		expired = timer.C
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-expired:
		return fmt.Errorf("timed out after %s", timeout)
	case <-token.Done():
		return token.Error()
	}
}
