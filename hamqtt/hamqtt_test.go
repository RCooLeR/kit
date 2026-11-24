package hamqtt

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestDiscoveryTopic(t *testing.T) {
	topic, err := DiscoveryTopic("homeassistant/", Sensor, "my_service", "queue_length")
	if err != nil || topic != "homeassistant/sensor/my_service/queue_length/config" {
		t.Fatalf("DiscoveryTopic = %q, %v", topic, err)
	}
	for _, bad := range [][4]string{
		{"", Sensor, "node", "object"},
		{"home/+", Sensor, "node", "object"},
		{"homeassistant", "Sensor", "node", "object"},
		{"homeassistant", Sensor, "my-service", "object"},
		{"homeassistant", Sensor, "node", "Queue"},
		{"homeassistant", Sensor, "node", ""},
	} {
		if _, err := DiscoveryTopic(bad[0], bad[1], bad[2], bad[3]); !errors.Is(err, ErrInvalidID) {
			t.Errorf("DiscoveryTopic(%v) = %v, want ErrInvalidID", bad, err)
		}
	}
	if id, err := EntityID(BinarySensor, "my_service_online"); err != nil || id != "binary_sensor.my_service_online" {
		t.Fatalf("EntityID = %q, %v", id, err)
	}
	if _, err := EntityID(Sensor, "my.service"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("EntityID with a dot = %v, want ErrInvalidID", err)
	}
}

func TestConfigEncodesWhatHomeAssistantReads(t *testing.T) {
	config := Config{
		Name: "Queue length", UniqueID: "my_service_queue_length", DefaultEntityID: "sensor.my_service_queue_length",
		StateTopic: "my-service/state", ValueTemplate: "{{ value_json.queue }}", StateClass: "measurement",
		Availability: Availability("my-service/availability"),
		Device:       Device{Identifiers: []string{"my_service"}, Name: "My service"},
	}
	if err := config.Validate(Sensor); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"name":"Queue length","unique_id":"my_service_queue_length","default_entity_id":"sensor.my_service_queue_length",` +
		`"state_topic":"my-service/state","value_template":"{{ value_json.queue }}","state_class":"measurement",` +
		`"availability":[{"topic":"my-service/availability"}],"device":{"identifiers":["my_service"],"name":"My service"}}`
	if string(raw) != want {
		t.Fatalf("payload\n%s\nwant\n%s", raw, want)
	}
}

func TestValidateRefusesWhatWouldMakeAStrayEntity(t *testing.T) {
	good := Config{Name: "N", UniqueID: "u", StateTopic: "s", Device: Device{Identifiers: []string{"d"}, Name: "D"}}
	tests := map[string]func(Config) Config{
		"no name":                   func(c Config) Config { c.Name = " "; return c },
		"a unique id with a dash":   func(c Config) Config { c.UniqueID = "my-id"; return c },
		"a wildcard state topic":    func(c Config) Config { c.StateTopic = "my/#"; return c },
		"a device without a name":   func(c Config) Config { c.Device.Name = ""; return c },
		"an entity of another kind": func(c Config) Config { c.DefaultEntityID = "binary_sensor.u"; return c },
		"an entity without a kind":  func(c Config) Config { c.DefaultEntityID = "u"; return c },
	}
	for name, change := range tests {
		if err := change(good).Validate(Sensor); err == nil {
			t.Errorf("%s: Validate accepted it", name)
		}
	}
}
