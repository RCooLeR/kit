// Package hamqtt builds Home Assistant MQTT discovery messages: the retained config a service
// publishes so that Home Assistant creates its entities, under
// <discovery prefix>/<component>/<node id>/<object id>/config.
//
// The package names nothing: the discovery prefix, the node and object IDs, the unique IDs and the
// entity IDs are the caller's, because entity IDs are what dashboards and automations read. It
// checks them, so a typo fails at start instead of creating a stray entity.
//
//	topic, _ := hamqtt.DiscoveryTopic("homeassistant", hamqtt.Sensor, "my_service", "queue_length")
//	payload, _ := json.Marshal(hamqtt.Config{
//		Name: "Queue length", UniqueID: "my_service_queue_length",
//		DefaultEntityID: "sensor.my_service_queue_length",
//		StateTopic: "my-service/state", ValueTemplate: "{{ value_json.queue }}",
//		StateClass: "measurement", Availability: hamqtt.Availability("my-service/availability"),
//		Device: device,
//	})
//
// The package depends on the standard library only.
package hamqtt

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Components a service publishes most; any Home Assistant MQTT component name works.
const (
	Sensor       = "sensor"
	BinarySensor = "binary_sensor"
)

// idPattern is what Home Assistant accepts in node and object IDs and in the object part of an
// entity ID.
var idPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// componentPattern is the shape of a Home Assistant component (domain) name.
var componentPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ErrInvalidID means a component, node, object or entity ID has characters Home Assistant refuses.
var ErrInvalidID = errors.New("hamqtt: invalid id")

// DiscoveryTopic returns <prefix>/<component>/<node id>/<object id>/config.
func DiscoveryTopic(prefix, component, nodeID, objectID string) (string, error) {
	prefix = strings.Trim(prefix, "/")
	switch {
	case prefix == "" || strings.ContainsAny(prefix, "+#"):
		return "", fmt.Errorf("%w: discovery prefix %q", ErrInvalidID, prefix)
	case !componentPattern.MatchString(component):
		return "", fmt.Errorf("%w: component %q", ErrInvalidID, component)
	case !idPattern.MatchString(nodeID):
		return "", fmt.Errorf("%w: node id %q", ErrInvalidID, nodeID)
	case !idPattern.MatchString(objectID):
		return "", fmt.Errorf("%w: object id %q", ErrInvalidID, objectID)
	}
	return prefix + "/" + component + "/" + nodeID + "/" + objectID + "/config", nil
}

// EntityID returns "<component>.<object>", the entity ID a Config asks for with DefaultEntityID.
func EntityID(component, object string) (string, error) {
	if !componentPattern.MatchString(component) || !idPattern.MatchString(object) {
		return "", fmt.Errorf("%w: entity %s.%s", ErrInvalidID, component, object)
	}
	return component + "." + object, nil
}

// Device groups a service's entities in Home Assistant.
type Device struct {
	Identifiers  []string `json:"identifiers"`
	Name         string   `json:"name"`
	Manufacturer string   `json:"manufacturer,omitempty"`
	Model        string   `json:"model,omitempty"`
	SWVersion    string   `json:"sw_version,omitempty"`
}

// AvailabilityTopic is one topic whose payload says whether the entity's source is reachable.
type AvailabilityTopic struct {
	Topic               string `json:"topic"`
	PayloadAvailable    string `json:"payload_available,omitempty"`
	PayloadNotAvailable string `json:"payload_not_available,omitempty"`
}

// Availability is the usual availability list: one topic with Home Assistant's default
// "online" and "offline" payloads.
func Availability(topic string) []AvailabilityTopic {
	return []AvailabilityTopic{{Topic: topic}}
}

// Config is the discovery config of one entity. Fields left empty are left out.
type Config struct {
	Name     string `json:"name"`
	UniqueID string `json:"unique_id"`
	// DefaultEntityID is the entity ID Home Assistant gives the entity when it creates it, such as
	// "sensor.my_service_queue_length". Without it the ID is derived from the names.
	DefaultEntityID     string              `json:"default_entity_id,omitempty"`
	StateTopic          string              `json:"state_topic"`
	ValueTemplate       string              `json:"value_template,omitempty"`
	UnitOfMeasurement   string              `json:"unit_of_measurement,omitempty"`
	DeviceClass         string              `json:"device_class,omitempty"`
	StateClass          string              `json:"state_class,omitempty"`
	EntityCategory      string              `json:"entity_category,omitempty"`
	Icon                string              `json:"icon,omitempty"`
	PayloadOn           string              `json:"payload_on,omitempty"`
	PayloadOff          string              `json:"payload_off,omitempty"`
	JSONAttributesTopic string              `json:"json_attributes_topic,omitempty"`
	Availability        []AvailabilityTopic `json:"availability,omitempty"`
	// ExpireAfter, in seconds, makes the entity unavailable when no state came for that long.
	ExpireAfter int    `json:"expire_after,omitempty"`
	Device      Device `json:"device"`
}

// Validate checks what Home Assistant needs to create the entity of component.
func (c Config) Validate(component string) error {
	switch {
	case strings.TrimSpace(c.Name) == "":
		return errors.New("hamqtt: name is required")
	case !idPattern.MatchString(c.UniqueID):
		return fmt.Errorf("%w: unique id %q", ErrInvalidID, c.UniqueID)
	case c.StateTopic == "" || strings.ContainsAny(c.StateTopic, "+#"):
		return fmt.Errorf("hamqtt: state topic %q must be a plain topic", c.StateTopic)
	case len(c.Device.Identifiers) == 0 || c.Device.Name == "":
		return errors.New("hamqtt: the device needs identifiers and a name")
	}
	if c.DefaultEntityID != "" {
		domain, object, found := strings.Cut(c.DefaultEntityID, ".")
		if !found || domain != component || !idPattern.MatchString(object) {
			return fmt.Errorf("%w: default entity id %q for a %s", ErrInvalidID, c.DefaultEntityID, component)
		}
	}
	return nil
}
