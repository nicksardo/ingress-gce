/*
Copyright 2018 The Kubernetes Authors.

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

package loadbalancers

import (
	"github.com/golang/glog"
	compute "google.golang.org/api/compute/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/ingress-gce/pkg/utils"
	"k8s.io/kubernetes/pkg/cloudprovider/providers/gce/cloud"
)

func (l *L7s) ensureTargetHttpProxy(lb *L7RuntimeInfo) error {
	proxyName := l.namer.TargetProxy(l.Name, utils.HTTPProtocol)
	urlMapId := cloud.NewUrlMapsResourceID("TODO-project", l.namer.UrlMap(lb.Name))
	urlMapLink := urlMapId.SelfLink(version.GA)

	proxy, err := l.cloud.GetTargetHttpProxy(proxyName)
	if utils.IgnoreHTTPNotFound(err) != nil {
		return err
	}

	expectedProxy := &compute.TargetHttpProxy{
		Name:   proxyName,
		UrlMap: urlMapLink,
	}

	if proxy == nil {
		glog.V(3).Infof("Creating TargetHttpProxy %q", proxyName)
		if err = l.cloud.CreateTargetHttpProxy(expectedProxy); err != nil {
			return err
		}
		lb.Generated.tp = expectedProxy
		return nil
	}

	if utils.EqualResourceNames(proxy.UrlMap, expectedProxy.UrlMap) {
		return nil
	}

	glog.V(3).Infof("Setting URLMap of TargetHttpProxy %q: %q to %q", proxy.Name, proxy.UrlMap, urlMapLink)
	if err := l.cloud.SetUrlMapForTargetHttpProxy(proxy, &compute.UrlMap{SelfLink: urlMapLink}); err != nil {
		return err
	}

	lb.Generated.tp = expectedProxy
	return nil
}

func (l *L7s) ensureTargetHttpsProxy(lb *L7RuntimeInfo) error {
	proxyName := l.namer.TargetProxy(l.Name, utils.HTTPSProtocol)
	urlMapId := cloud.NewUrlMapsResourceID("TODO-project", l.namer.UrlMap(lb.Name))
	urlMapLink := urlMapId.SelfLink(version.GA)

	proxy, err := l.cloud.GetTargetHttpProxy(proxyName)
	if utils.IgnoreHTTPNotFound(err) != nil {
		return err
	}

	expectedProxy := &compute.TargetHttpsProxy{
		Name:   proxyName,
		UrlMap: urlMapLink,
	}
	for _, c := range l.sslCerts {
		id := cloud.NewSslCertificatesResourceID("TODO-project", c.Name)
		cLink := id.SelfLink(version.GA)
		expectedProxy.SslCertificates = append(expectedProxy.SslCertificates, cLink)
	}

	if proxy == nil {
		glog.V(3).Infof("Creating TargetHttpsProxy %q", proxyName)
		if err = l.cloud.CreateTargetHttpsProxy(expectedProxy); err != nil {
			return err
		}

		l.tps = expectedProxy
		return nil
	}

	if !utils.EqualResourceNames(proxy.UrlMap, expectedProxy.UrlMap) {
		glog.V(3).Infof("Setting URLMap of TargetHttpsProxy %q: %q to %q", proxy.Name, proxy.UrlMap, urlMapLink)
		if err := l.cloud.SetUrlMapForTargetHttpsProxy(proxy, &compute.UrlMap{SelfLink: urlMapLink}); err != nil {
			return err
		}
	}

	if !sets.NewString(proxy.SslCertificates...).Equal(sets.NewString(expectedProxy.SslCertificates...)) {
		glog.V(3).Infof("Setting certificates for TargetHttpsProxy %q: %v", proxy.Name, expectedProxy.SslCertificates)
		if err := l.cloud.SetSslCertificateForTargetHttpsProxy(proxy, expectedProxy.SslCertificates); err != nil {
			return err
		}

	}
	l.tps = expectedProxy
	return nil
}
