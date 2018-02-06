/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"net/http"

	"github.com/golang/glog"

	compute "google.golang.org/api/compute/v1"
	gce "k8s.io/kubernetes/pkg/cloudprovider/providers/gce"

	"k8s.io/ingress-gce/pkg/backends"
	"k8s.io/ingress-gce/pkg/firewalls"
	"k8s.io/ingress-gce/pkg/flags"
	"k8s.io/ingress-gce/pkg/healthchecks"
	"k8s.io/ingress-gce/pkg/instances"
	"k8s.io/ingress-gce/pkg/loadbalancers"
	"k8s.io/ingress-gce/pkg/utils"
)

const (
	defaultPort            = 80
	defaultHealthCheckPath = "/"
)

// ClusterManager manages cluster resource pools.
type ClusterManager struct {
	ClusterNamer           *utils.Namer
	defaultBackendNodePort backends.ServicePort
	instancePool           instances.NodePool
	backendPool            backends.BackendPool
	l7Pool                 loadbalancers.LoadBalancerPool
	firewallPool           firewalls.SingleFirewallPool

	// TODO: Refactor so we simply init a health check pool.
	// Currently health checks are tied to backends because each backend needs
	// the link of the associated health, but both the backend pool and
	// loadbalancer pool manage backends, because the lifetime of the default
	// backend is tied to the last/first loadbalancer not the life of the
	// nodeport service or Ingress.
	healthCheckers []healthchecks.HealthChecker
}

// Init initializes the cluster manager.
func (c *ClusterManager) Init(zl instances.ZoneLister, pp backends.ProbeProvider) {
	c.instancePool.Init(zl)
	c.backendPool.Init(pp)
	// TODO: Initialize other members as needed.
}

// IsHealthy returns an error if the cluster manager is unhealthy.
func (c *ClusterManager) IsHealthy() (err error) {
	// TODO: Expand on this, for now we just want to detect when the GCE client
	// is broken.
	_, err = c.backendPool.List()

	// If this container is scheduled on a node without compute/rw it is
	// effectively useless, but it is healthy. Reporting it as unhealthy
	// will lead to container crashlooping.
	if utils.IsHTTPErrorCode(err, http.StatusForbidden) {
		glog.Infof("Reporting cluster as healthy, but unable to list backends: %v", err)
		return nil
	}
	return
}

func (c *ClusterManager) shutdown() error {
	if err := c.l7Pool.Shutdown(); err != nil {
		return err
	}
	if err := c.firewallPool.Shutdown(); err != nil {
		if _, ok := err.(*firewalls.FirewallSyncError); ok {
			return nil
		}
		return err
	}
	// The backend pool will also delete instance groups.
	return c.backendPool.Shutdown()
}

// Checkpoint performs a checkpoint with the cloud.
// - lbs are the single cluster L7 loadbalancers we wish to exist. If they already
//   exist, they should not have any broken links between say, a UrlMap and
//   TargetHttpProxy.
// - nodeNames are the names of nodes we wish to add to all loadbalancer
//   instance groups.
// - backendServicePorts are the ports for which we require BackendServices.
// - namedPorts are the ports which must be opened on instance groups.
// - firewallPorts are the ports which must be opened in the firewall rule.
// Returns the list of all instance groups corresponding to the given loadbalancers.
// If in performing the checkpoint the cluster manager runs out of quota, a
// googleapi 403 is returned.
func (c *ClusterManager) Checkpoint(lb *loadbalancers.L7RuntimeInfo, nodeNames []string, backendServicePorts []backends.ServicePort, namedPorts []backends.ServicePort, endpointPorts []string) ([]*compute.InstanceGroup, error) {
	glog.V(4).Infof("Checkpoint(%v, %v nodeNames, %v backendServicePorts, %v namedPorts, %v endpointPorts)", lb.String(), len(nodeNames), len(backendServicePorts), len(namedPorts), len(endpointPorts))

	if len(namedPorts) != 0 {
		// Add the default backend node port to the list of named ports for instance groups.
		namedPorts = append(namedPorts, c.defaultBackendNodePort)
	}
	// Multiple ingress paths can point to the same service (and hence nodePort)
	// but each nodePort can only have one set of cloud resources behind it. So
	// don't waste time double validating GCE BackendServices.
	namedPorts = uniq(namedPorts)
	backendServicePorts = uniq(backendServicePorts)
	// Create Instance Groups.
	igs, err := c.EnsureInstanceGroupsAndPorts(namedPorts)
	if err != nil {
		return igs, err
	}
	if err := c.backendPool.Ensure(backendServicePorts, igs); err != nil {
		return igs, err
	}
	if err := c.instancePool.Sync(nodeNames); err != nil {
		return igs, err
	}
	if err := c.l7Pool.Sync(lb); err != nil {
		return igs, err
	}

	if err := c.firewallPool.Sync(nodeNames, endpointPorts...); err != nil {
		return igs, err
	}

	return igs, nil
}

func (c *ClusterManager) EnsureInstanceGroupsAndPorts(servicePorts []backends.ServicePort) ([]*compute.InstanceGroup, error) {
	ports := []int64{}
	for _, p := range servicePorts {
		ports = append(ports, p.NodePort)
	}
	igs, err := instances.EnsureInstanceGroupsAndPorts(c.instancePool, c.ClusterNamer, ports)
	return igs, err
}

// GC garbage collects unused resources.
// - lbNames are the names of L7 loadbalancers we wish to exist. Those not in
//   this list are removed from the cloud.
// - nodePorts are the ports for which we want BackendServies. BackendServices
//   for ports not in this list are deleted.
// This method ignores googleapi 404 errors (StatusNotFound).
func (c *ClusterManager) GC(lbNames []string, nodePorts []backends.ServicePort) error {
	// On GC:
	// * Loadbalancers need to get deleted before backends.
	// * Backends are refcounted in a shared pool.
	// * We always want to GC backends even if there was an error in GCing
	//   loadbalancers, because the next Sync could rely on the GC for quota.
	// * There are at least 2 cases for backend GC:
	//   1. The loadbalancer has been deleted.
	//   2. An update to the url map drops the refcount of a backend. This can
	//      happen when an Ingress is updated, if we don't GC after the update
	//      we'll leak the backend.
	lbErr := c.l7Pool.GC(lbNames)
	beErr := c.backendPool.GC(nodePorts)
	if lbErr != nil {
		return lbErr
	}
	if beErr != nil {
		return beErr
	}

	// TODO(ingress#120): Move this to the backend pool so it mirrors creation
	if len(lbNames) == 0 {
		igName := c.ClusterNamer.InstanceGroup()
		glog.Infof("Deleting instance group %v", igName)
		if err := c.instancePool.DeleteInstanceGroup(igName); err != err {
			return err
		}
		glog.V(2).Infof("Shutting down firewall as there are no loadbalancers")
		c.firewallPool.Shutdown()
	}

	return nil
}

func (c *ClusterManager) BackendServiceForPort(port int64) (*compute.BackendService, error) {
	return c.backendPool.Get(port)
}

func (c *ClusterManager) DefaultBackendNodePort() *backends.ServicePort {
	return &c.defaultBackendNodePort
}

// NewClusterManager creates a cluster manager for shared resources.
// - namer: is the namer used to tag cluster wide shared resources.
// - defaultBackendNodePort: is the node port of glbc's default backend. This is
//	 the kubernetes Service that serves the 404 page if no urls match.
// - defaultHealthCheckPath: is the default path used for L7 health checks, eg: "/healthz".
func NewClusterManager(
	cloud *gce.GCECloud,
	namer *utils.Namer,
	defaultBackendNodePort backends.ServicePort,
	defaultHealthCheckPath string) (*ClusterManager, error) {

	// Names are fundamental to the cluster, the uid allocator makes sure names don't collide.
	cluster := ClusterManager{ClusterNamer: namer}

	// NodePool stores GCE vms that are in this Kubernetes cluster.
	cluster.instancePool = instances.NewNodePool(cloud, namer)

	// BackendPool creates GCE BackendServices and associated health checks.
	healthChecker := healthchecks.NewHealthChecker(cloud, defaultHealthCheckPath, cluster.ClusterNamer)
	// TODO(nicksardo): delete this healthchecker
	defaultBackendHealthChecker := healthchecks.NewHealthChecker(cloud, "/healthz", cluster.ClusterNamer)

	cluster.healthCheckers = []healthchecks.HealthChecker{healthChecker, defaultBackendHealthChecker}

	cluster.backendPool = backends.NewBackendPool(cloud, cloud, healthChecker, cluster.instancePool, cluster.ClusterNamer, []int64{defaultBackendNodePort.Port}, true)
	cluster.defaultBackendNodePort = defaultBackendNodePort

	// L7 pool creates targetHTTPProxy, ForwardingRules, UrlMaps, StaticIPs.
	cluster.l7Pool = loadbalancers.NewLoadBalancerPool(cloud, defaultBackendPool, defaultBackendNodePort, cluster.ClusterNamer)
	cluster.firewallPool = firewalls.NewFirewallPool(cloud, cluster.ClusterNamer, gce.LoadBalancerSrcRanges(), flags.F.NodePortRanges.Values())
	return &cluster, nil
}
