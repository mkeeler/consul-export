package export

import (
	"context"
	"fmt"

	"github.com/hashicorp/consul/api"
)

func Export(client *api.Client, excludeTypes map[string]struct{}) (*Data, error) {
	e, err := newExporter(client, excludeTypes)
	if err != nil {
		return nil, err
	}
	return e.Export()
}

type exporter struct {
	client       *api.Client
	excludeTypes map[string]struct{}
	enterprise   bool
}

func newExporter(client *api.Client, excludeTypes map[string]struct{}) (*exporter, error) {
	ent, err := isEnterprise(client)
	if err != nil {
		return nil, fmt.Errorf("error determining whether Consul is CE or Enterprise: %w", err)
	}

	return &exporter{
		client:       client,
		excludeTypes: excludeTypes,
		enterprise:   ent,
	}, nil
}

func (e *exporter) Export() (*Data, error) {
	pdata, err := e.exportPartitions()
	if err != nil {
		return nil, fmt.Errorf("error exporting partitions: %w", err)
	}

	return &Data{
		Partitions: pdata,
	}, nil
}

func (e *exporter) exportPartitions() (map[string]PartitionData, error) {
	var partitions []*api.Partition
	var err error
	if e.enterprise {
		partitions, _, err = e.client.Partitions().List(context.Background(), nil)
		if err != nil {
			return nil, fmt.Errorf("error listing partitions: %w", err)
		}
	} else {
		partitions = []*api.Partition{
			{
				Name: "default",
			},
		}
	}

	pmap := make(map[string]PartitionData)

	for _, partition := range partitions {
		pdata, err := e.exportPartition(partition.Name)
		if err != nil {
			return nil, fmt.Errorf("error exporting partition %s: %w", partition.Name, err)
		}

		pmap[partition.Name] = PartitionData{
			Definition:      partition,
			PartitionedData: *pdata,
		}
	}

	return pmap, nil
}

func (e *exporter) exportPartition(partition string) (*PartitionedData, error) {
	nodes, err := e.exportNodes(partition)
	if err != nil {
		return nil, fmt.Errorf("error exporting nodes for partition %s: %w", partition, err)
	}

	namespaces, err := e.exportNamespaces(partition)
	if err != nil {
		return nil, fmt.Errorf("error exporting namespaces for partition %s: %w", partition, err)
	}

	return &PartitionedData{
		Namespaces: namespaces,
		Nodes:      nodes,
	}, nil
}

func (e *exporter) exportNamespaces(partition string) (map[string]NamespaceData, error) {
	var namespaces []*api.Namespace
	var err error
	if e.enterprise {
		namespaces, _, err = e.client.Namespaces().List(e.queryOptionsWithTenant(partition, ""))
		if err != nil {
			return nil, fmt.Errorf("error listing namespace: %w", err)
		}
	} else {
		namespaces = []*api.Namespace{
			{
				Name: "default",
			},
		}
	}

	nmap := make(map[string]NamespaceData)

	for _, namespace := range namespaces {
		ndata, err := e.exportNamespace(partition, namespace.Name)
		if err != nil {
			return nil, fmt.Errorf("error exporting namespace %s in partition %s: %w", namespace.Name, partition, err)
		}

		nmap[namespace.Name] = NamespaceData{
			Definition:     namespace,
			NamespacedData: *ndata,
		}
	}

	return nmap, nil
}

func (e *exporter) exportNamespace(partition, namespace string) (*NamespacedData, error) {
	acls, err := e.exportACLs(partition, namespace)
	if err != nil {
		return nil, fmt.Errorf("error exporting ACL data for namespace %s in partition %s: %w", namespace, partition, err)
	}

	configEntries, err := e.exportConfigEntries(partition, namespace)
	if err != nil {
		return nil, fmt.Errorf("error exporting config entry data for namespace %s in partition %s: %w", namespace, partition, err)
	}

	services, err := e.exportServices(partition, namespace)
	if err != nil {
		return nil, fmt.Errorf("error exporting services for namespace %s in partition %s: %w", namespace, partition, err)
	}

	return &NamespacedData{
		ACLs:          acls,
		ConfigEntries: configEntries,
		Services:      services,
	}, nil
}

func (e *exporter) exportNodes(partition string) (map[string]NodeData, error) {
	if !e.shouldExportType("catalog") {
		return nil, nil
	}
	opts := e.queryOptionsWithTenant(partition, "")
	nodes, _, err := e.client.Catalog().Nodes(opts)
	if err != nil {
		return nil, fmt.Errorf("error listing nodes in partition %s: %w", partition, err)
	}

	nmap := make(map[string]NodeData)

	for _, node := range nodes {
		ndata := NodeData{
			Definition:   *node,
			HealthChecks: make(map[string]api.HealthCheck),
		}

		checks, _, err := e.client.Health().Node(node.Node, opts)
		if err != nil {
			return nil, fmt.Errorf("error listing health checks for node %s: %w", node.Node, err)
		}

		for _, check := range checks {
			ndata.HealthChecks[check.CheckID] = *check
		}

		nmap[node.Node] = ndata
	}

	return nmap, nil
}

func (e *exporter) exportACLs(partition, namespace string) (*ACLData, error) {
	if !e.shouldExportType("acls") {
		return nil, nil
	}

	policies, err := e.exportACLPolicies(partition, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to export acl policies: %w", err)
	}

	roles, err := e.exportACLRoles(partition, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to export acl roles: %w", err)
	}

	tokens, err := e.exportACLTokens(partition, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to export acl tokens: %w", err)
	}

	methods, err := e.exportACLAuthMethods(partition, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to export acl auth methods: %w", err)
	}

	bindingRules, err := e.exportACLBindingRules(partition, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to export acl binding rules in tenant: %w", err)
	}

	return &ACLData{
		Policies:     policies,
		Roles:        roles,
		Tokens:       tokens,
		AuthMethods:  methods,
		BindingRules: bindingRules,
	}, nil
}

func (e *exporter) exportACLPolicies(partition, namespace string) (map[string]api.ACLPolicy, error) {
	acls := e.client.ACL()
	opts := e.queryOptionsWithTenant(partition, namespace)

	policyList, _, err := acls.PolicyList(opts)
	if err != nil {
		return nil, fmt.Errorf("error listing policies: %w", err)
	}

	policies := make(map[string]api.ACLPolicy)
	for _, policyStub := range policyList {
		policy, _, err := acls.PolicyRead(policyStub.ID, opts)
		if err != nil {
			return nil, fmt.Errorf("error reading policy: %w", err)
		}

		policies[policy.ID] = *policy
	}

	return policies, nil
}

func (e *exporter) exportACLRoles(partition, namespace string) (map[string]api.ACLRole, error) {
	acls := e.client.ACL()
	opts := e.queryOptionsWithTenant(partition, namespace)

	roleList, _, err := acls.RoleList(opts)
	if err != nil {
		return nil, fmt.Errorf("error listing roles: %w", err)
	}

	roles := make(map[string]api.ACLRole)
	for _, roleStub := range roleList {
		role, _, err := acls.RoleRead(roleStub.ID, opts)
		if err != nil {
			return nil, fmt.Errorf("error reading role: %w", err)
		}

		roles[role.ID] = *role
	}

	return roles, nil
}

func (e *exporter) exportACLTokens(partition, namespace string) (map[string]api.ACLToken, error) {
	acls := e.client.ACL()
	opts := e.queryOptionsWithTenant(partition, namespace)

	tokenList, _, err := acls.TokenList(opts)
	if err != nil {
		return nil, fmt.Errorf("error listing tokens: %w", err)
	}

	tokens := make(map[string]api.ACLToken)
	for _, tokenStub := range tokenList {
		token, _, err := acls.TokenRead(tokenStub.AccessorID, opts)
		if err != nil {
			return nil, fmt.Errorf("error reading token: %w", err)
		}

		tokens[token.AccessorID] = *token
	}

	return tokens, nil
}

func (e *exporter) exportACLAuthMethods(partition, namespace string) (map[string]api.ACLAuthMethod, error) {
	acls := e.client.ACL()
	opts := e.queryOptionsWithTenant(partition, namespace)

	methodList, _, err := acls.AuthMethodList(opts)
	if err != nil {
		return nil, fmt.Errorf("error listing auth methods: %w", err)
	}

	methods := make(map[string]api.ACLAuthMethod)
	for _, methodEntry := range methodList {
		method, _, err := acls.AuthMethodRead(methodEntry.Name, opts)
		if err != nil {
			return nil, fmt.Errorf("error reading auth method: %w", err)
		}

		methods[method.Name] = *method
	}

	return methods, nil
}

func (e *exporter) exportACLBindingRules(partition, namespace string) (map[string]api.ACLBindingRule, error) {
	acls := e.client.ACL()
	opts := e.queryOptionsWithTenant(partition, namespace)

	ruleList, _, err := acls.BindingRuleList("", opts)
	if err != nil {
		return nil, fmt.Errorf("error listing auth methods: %w", err)
	}

	rules := make(map[string]api.ACLBindingRule)
	for _, rule := range ruleList {
		rules[rule.ID] = *rule
	}

	return rules, nil
}

func (e *exporter) exportConfigEntries(partition, namespace string) (*ConfigEntryData, error) {
	if !e.shouldExportType("config-entries") {
		return nil, nil
	}

	type kindConfig struct {
		kind       string
		enterprise bool
	}
	var kinds = []kindConfig{
		{kind: api.ServiceDefaults},
		{kind: api.ProxyDefaults},
		{kind: api.ServiceRouter},
		{kind: api.ServiceSplitter},
		{kind: api.ServiceResolver},
		{kind: api.IngressGateway},
		{kind: api.TerminatingGateway},
		{kind: api.ServiceIntentions},
		{kind: api.MeshConfig},
		{kind: api.ExportedServices},
		// {kind: api.SamenessGroup, enterprise: true},
		// {kind: api.RateLimitIPConfig, enterprise: true},
		// {kind: api.APIGateway},
		// {kind: api.TCPRoute},
		// {kind: api.InlineCertificate},
		// {kind: api.HTTPRoute},
		// {kind: api.JWTProvider},
	}

	entries := &ConfigEntryData{
		Kinds: make(map[string]ConfigEntryKindData),
	}

	for _, kind := range kinds {
		if !kind.enterprise || e.enterprise {
			kdata, err := e.exportConfigEntryKind(partition, namespace, kind.kind)
			if err != nil {
				return nil, fmt.Errorf("error exporting config entry kind %s: %w", kind.kind, err)
			}

			entries.Kinds[kind.kind] = kdata
		}
	}

	return entries, nil
}

func (e *exporter) exportConfigEntryKind(partition, namespace, kind string) (ConfigEntryKindData, error) {
	entries := make(map[string]api.ConfigEntry)

	opts := e.queryOptionsWithTenant(partition, namespace)
	entryList, _, err := e.client.ConfigEntries().List(kind, opts)
	if err != nil {
		return ConfigEntryKindData{}, fmt.Errorf("error listing config entries for kind %s: %w", kind, err)
	}

	for _, entry := range entryList {
		entries[entry.GetName()] = entry
	}

	return ConfigEntryKindData{Entries: entries}, nil
}

func (e *exporter) exportServices(partition, namespace string) (map[string]ServiceInstanceData, error) {
	if !e.shouldExportType("catalog") {
		return nil, nil
	}

	catalog := e.client.Catalog()
	health := e.client.Health()

	opts := e.queryOptionsWithTenant(partition, namespace)

	serviceNames, _, err := catalog.Services(opts)
	if err != nil {
		return nil, fmt.Errorf("error listing services: %w", err)
	}

	sdata := make(map[string]ServiceInstanceData)

	for serviceName := range serviceNames {
		entries, _, err := health.Service(serviceName, "", false, opts)
		if err != nil {
			return nil, fmt.Errorf("error listing service service health %s: %w", serviceName, err)
		}

		instanceData := ServiceInstanceData{
			Nodes: make(map[string]ServiceNodeInstanceData),
		}
		for _, entry := range entries {
			node, ok := instanceData.Nodes[entry.Node.Node]
			if !ok {
				node.Instances = make(map[string]api.ServiceEntry)
			}

			node.Instances[entry.Service.ID] = *entry
			instanceData.Nodes[entry.Node.Node] = node
		}

		sdata[serviceName] = instanceData
	}

	return sdata, nil
}

func (e *exporter) queryOptionsWithTenant(partition, namespace string) *api.QueryOptions {
	if !e.enterprise {
		return &api.QueryOptions{
			Partition: "",
			Namespace: "",
		}
	}
	return &api.QueryOptions{
		Partition: partition,
		Namespace: namespace,
	}
}

func (e *exporter) shouldExportType(dataType string) bool {
	_, ok := e.excludeTypes[dataType]
	return !ok
}
