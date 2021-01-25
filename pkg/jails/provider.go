package jails

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	// Provider configuration defaults.
	defaultCPUCapacity    = "20"
	defaultMemoryCapacity = "100Gi"
	defaultPodCapacity    = "20"
	defaultNodeIP         = "192.168.0.10"

	// Values used in tracing as attribute keys.
	namespaceKey     = "namespace"
	nameKey          = "name"
	containerNameKey = "containerName"
)

// JailsProvider implements the virtual-kubelet for FreeBSD Jails.
type JailsProvider struct {
	nodeName           string
	operatingSystem    string
	internalIP         string
	daemonEndpointPort int32
	pods               map[string]*v1.Pod
	config             JailsConfig
	startTime          time.Time
	notifier           func(*v1.Pod)
}

// JailsConfig contains a jails virtual-kubelet's configurable parameters.
type JailsConfig struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
	Pods   string `json:"pods,omitempty"`
	NodeIP string `json: "nodeip, omitempty"`
}

// NewJailsProviderConfig creates a new config
func NewJailsProviderConfig(config JailsConfig, nodeName, operatingSystem string, internalIP string, daemonEndpointPort int32) (*JailsProvider, error) {
	// set defaults
	if config.CPU == "" {
		config.CPU = defaultCPUCapacity
	}
	if config.Memory == "" {
		config.Memory = defaultMemoryCapacity
	}
	if config.Pods == "" {
		config.Pods = defaultPodCapacity
	}

	// TODO: Detect the IP instead of relying on the default one
	if config.NodeIP == "" {
		config.NodeIP = defaultNodeIP
	}
	provider := JailsProvider{
		nodeName:           nodeName,
		operatingSystem:    operatingSystem,
		internalIP:         config.NodeIP,
		daemonEndpointPort: daemonEndpointPort,
		pods:               make(map[string]*v1.Pod),
		config:             config,
		startTime:          time.Now(),
	}

	return &provider, nil
}

// NewJailsProvider creates a new JailsProvider, which implements the PodNotifier interface
func NewJailsProvider(providerConfig, nodeName, operatingSystem string, internalIP string, daemonEndpointPort int32) (*JailsProvider, error) {
	config, err := loadConfig(providerConfig, nodeName)
	if err != nil {
		return nil, err
	}

	return NewJailsProviderConfig(config, nodeName, operatingSystem, internalIP, daemonEndpointPort)
}

// loadConfig loads the given json configuration files.
// TODO: We can make better here. Maybe use YAML (aaaaaaaaaah!!) or see how to make a default config (flags?)
func loadConfig(providerConfig, nodeName string) (config JailsConfig, err error) {
	data, err := ioutil.ReadFile(providerConfig)
	if err != nil {
		return config, err
	}
	configMap := map[string]JailsConfig{}
	err = json.Unmarshal(data, &configMap)
	if err != nil {
		return config, err
	}
	if _, exist := configMap[nodeName]; exist {
		config = configMap[nodeName]
		if config.CPU == "" {
			config.CPU = defaultCPUCapacity
		}
		if config.Memory == "" {
			config.Memory = defaultMemoryCapacity
		}
		if config.Pods == "" {
			config.Pods = defaultPodCapacity
		}

		if config.NodeIP == "" {
			config.Pods = defaultNodeIP
		}
	}
	if _, err = resource.ParseQuantity(config.CPU); err != nil {
		return config, fmt.Errorf("Invalid CPU value %v", config.CPU)
	}
	if _, err = resource.ParseQuantity(config.Memory); err != nil {
		return config, fmt.Errorf("Invalid memory value %v", config.Memory)
	}
	if _, err = resource.ParseQuantity(config.Pods); err != nil {
		return config, fmt.Errorf("Invalid pods value %v", config.Pods)
	}
	return config, nil
}
