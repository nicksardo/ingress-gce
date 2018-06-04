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

package backends

import (
	"encoding/json"

	"github.com/golang/glog"

	computealpha "google.golang.org/api/compute/v0.alpha"
	compute "google.golang.org/api/compute/v1"
	api_v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/cloudprovider/providers/gce/cloud"
	"k8s.io/kubernetes/pkg/cloudprovider/providers/gce/cloud/meta"

	"k8s.io/ingress-gce/pkg/annotations"
	"k8s.io/ingress-gce/pkg/utils"
)

// NewFakeBackendServices creates a new fake backend services manager.
func NewFakeBackendServices(ef func(op int, be *computealpha.BackendService) error) *FakeBackendServices {
	return &FakeBackendServices{
		errFunc: ef,
		backendServices: cache.NewStore(func(obj interface{}) (string, error) {
			svc := obj.(*computealpha.BackendService)
			return svc.Name, nil
		}),
	}
}

// FakeBackendServices fakes out GCE backend services.
type FakeBackendServices struct {
	backendServices cache.Store
	calls           []int
	errFunc         func(op int, be *computealpha.BackendService) error
}

// GetGlobalBackendService fakes getting a backend service from the cloud.
func (f *FakeBackendServices) GetGlobalBackendService(name string) (*compute.BackendService, error) {
	svc, err := f.GetAlphaGlobalBackendService(name)
	if err != nil {
		return nil, err
	}

	if name == svc.Name {
		return toV1BackendService(svc), nil
	}

	return nil, utils.FakeGoogleAPINotFoundErr()
}

func (f *FakeBackendServices) GetAlphaGlobalBackendService(name string) (*computealpha.BackendService, error) {
	f.calls = append(f.calls, utils.Get)
	obj, exists, err := f.backendServices.GetByKey(name)
	if !exists {
		return nil, utils.FakeGoogleAPINotFoundErr()
	}
	if err != nil {
		return nil, err
	}

	svc := obj.(*computealpha.BackendService)

	if name == svc.Name {
		return svc, nil
	}

	return nil, utils.FakeGoogleAPINotFoundErr()
}

// CreateGlobalBackendService fakes backend service creation.
func (f *FakeBackendServices) CreateGlobalBackendService(be *compute.BackendService) error {
	return f.CreateAlphaGlobalBackendService(toAlphaBackendService(be))
}

// CreateGlobalBackendService fakes updating a backend service.
func (f *FakeBackendServices) CreateAlphaGlobalBackendService(be *computealpha.BackendService) error {
	if f.errFunc != nil {
		if err := f.errFunc(utils.Create, be); err != nil {
			return err
		}
	}

	f.calls = append(f.calls, utils.Create)
	be.SelfLink = cloud.NewBackendServicesResourceID("mock-project", be.Name).SelfLink(meta.VersionGA)
	return f.backendServices.Update(be)
}

// DeleteGlobalBackendService fakes backend service deletion.
func (f *FakeBackendServices) DeleteGlobalBackendService(name string) error {
	f.calls = append(f.calls, utils.Delete)
	svc, exists, err := f.backendServices.GetByKey(name)
	if !exists {
		return utils.FakeGoogleAPINotFoundErr()
	}
	if err != nil {
		return err
	}

	if f.errFunc != nil {
		if err := f.errFunc(utils.Delete, svc.(*computealpha.BackendService)); err != nil {
			return err
		}
	}
	return f.backendServices.Delete(svc)
}

// ListGlobalBackendServices fakes backend service listing.
func (f *FakeBackendServices) ListGlobalBackendServices() ([]*compute.BackendService, error) {
	var svcs []*compute.BackendService
	for _, s := range f.backendServices.List() {
		svc := toV1BackendService(s.(*computealpha.BackendService))
		svcs = append(svcs, svc)
	}
	return svcs, nil
}

// UpdateGlobalBackendService fakes updating a backend service.
func (f *FakeBackendServices) UpdateGlobalBackendService(be *compute.BackendService) error {
	return f.UpdateAlphaGlobalBackendService(toAlphaBackendService(be))
}

// UpdateGlobalBackendService fakes updating a backend service.
func (f *FakeBackendServices) UpdateAlphaGlobalBackendService(be *computealpha.BackendService) error {
	if f.errFunc != nil {
		if err := f.errFunc(utils.Update, be); err != nil {
			return err
		}
	}
	f.calls = append(f.calls, utils.Update)
	glog.V(2).Infof("update backend service %+v", be)
	return f.backendServices.Update(be)
}

// GetGlobalBackendServiceHealth fakes getting backend service health.
func (f *FakeBackendServices) GetGlobalBackendServiceHealth(name, instanceGroupLink string) (*compute.BackendServiceGroupHealth, error) {
	be, err := f.GetGlobalBackendService(name)
	if err != nil {
		return nil, err
	}
	states := []*compute.HealthStatus{
		{
			HealthState: "HEALTHY",
			IpAddress:   "",
			Port:        be.Port,
		},
	}
	return &compute.BackendServiceGroupHealth{
		HealthStatus: states}, nil
}

// FakeProbeProvider implements the probeProvider interface for tests.
type FakeProbeProvider struct {
	probes map[utils.ServicePort]*api_v1.Probe
}

// NewFakeProbeProvider returns a struct which satisfies probeProvider interface
func NewFakeProbeProvider(probes map[utils.ServicePort]*api_v1.Probe) *FakeProbeProvider {
	return &FakeProbeProvider{probes}
}

// GetProbe returns the probe for a given nodePort
func (pp *FakeProbeProvider) GetProbe(port utils.ServicePort) (*api_v1.Probe, error) {
	if probe, exists := pp.probes[port]; exists && probe.HTTPGet != nil {
		return probe, nil
	}
	return nil, nil
}

func toV1BackendService(be *computealpha.BackendService) *compute.BackendService {
	bytes, _ := be.MarshalJSON()
	res := &compute.BackendService{}
	json.Unmarshal(bytes, res)

	// Currently, getting an Alpha BackendService strips it of Protocol if HTTP2.
	// TODO: remove this check once ProtocolHTTP2 moves into Beta or GA.
	if res.Protocol == string(annotations.ProtocolHTTP2) {
		res.Protocol = ""
	}
	return res
}

func toAlphaBackendService(be *compute.BackendService) *computealpha.BackendService {
	bytes, _ := be.MarshalJSON()
	res := &computealpha.BackendService{}
	json.Unmarshal(bytes, res)
	return res
}
