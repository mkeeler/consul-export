package export

import "github.com/hashicorp/consul/api"

type Data struct {
	Partitions map[string]PartitionData `json:"partitions,omitempty"`
}

type PartitionData struct {
	Definition *api.Partition `json:"definition"`
	PartitionedData
}

type PartitionedData struct {
	Namespaces map[string]NamespaceData `json:"namespaces,omitempty"`
	Nodes      map[string]NodeData      `json:"nodes,omitempty"`
}

type NodeData struct {
	Definition   api.Node                   `json:"definition"`
	HealthChecks map[string]api.HealthCheck `json:"health_checks,omitempty"`
}

type NamespaceData struct {
	Definition *api.Namespace `json:"definition"`
	NamespacedData
}

type NamespacedData struct {
	ACLs          *ACLData                       `json:"acls,omitempty"`
	ConfigEntries *ConfigEntryData               `json:"config_entries,omitempty"`
	Services      map[string]ServiceInstanceData `json:"services,omitempty"`
}

type ServiceInstanceData struct {
	Nodes map[string]ServiceNodeInstanceData `json:"nodes,omitempty"`
}

type ServiceNodeInstanceData struct {
	Instances map[string]api.ServiceEntry `json:"instances,omitempty"`
}

type ACLData struct {
	// Policies is a mapping of the policy id to the policy definition
	Policies map[string]api.ACLPolicy `json:"policies,omitempty"`
	// Roles is a mapping of the role id to the role definition
	Roles map[string]api.ACLRole `json:"roles,omitempty"`
	// Tokens is a map of accessor id to acl token definition
	Tokens map[string]api.ACLToken `json:"tokens,omitempty"`
	// AuthMethods is a map of auth method names to auth method definitions
	AuthMethods map[string]api.ACLAuthMethod `json:"auth_methods,omitempty"`
	// BindingRules is a map of binding rule ids to binding rule definitions
	BindingRules map[string]api.ACLBindingRule `json:"binding_rules,omitempty"`
}

type ConfigEntryData struct {
	// Kinds is a map of config entry kinds to the config entry data
	Kinds map[string]ConfigEntryKindData `json:"kinds,omitempty"`
}

type ConfigEntryKindData struct {
	// Entries is a map of config entry names to the config entry definition
	Entries map[string]api.ConfigEntry `json:"entries,omitempty"`
}
