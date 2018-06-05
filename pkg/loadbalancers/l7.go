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

package loadbalancers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang/glog"

	compute "google.golang.org/api/compute/v1"

	"k8s.io/ingress-gce/pkg/annotations"
	"k8s.io/ingress-gce/pkg/backends"
	"k8s.io/ingress-gce/pkg/utils"
)

const (
	// The gce api uses the name of a path rule to match a host rule.
	hostRulePrefix = "host"

	// DefaultHost is the host used if none is specified. It is a valid value
	// for the "Host" field recognized by GCE.
	DefaultHost = "*"

	// DefaultPath is the path used if none is specified. It is a valid path
	// recognized by GCE.
	DefaultPath = "/*"

	httpDefaultPortRange  = "80-80"
	httpsDefaultPortRange = "443-443"

	// Every target https proxy accepts upto 10 ssl certificates.
	TargetProxyCertLimit = 10
)

// L7RuntimeInfo is info passed to this module from the controller runtime.
type L7RuntimeInfo struct {
	// Name is the name of a loadbalancer.
	Name string
	// IP is the desired ip of the loadbalancer, eg from a staticIP.
	IP string
	// TLS are the tls certs to use in termination.
	TLS []*TLSCerts
	// TLSName is the name of the preshared cert to use. Multiple certs can be specified as a comma-separated string
	TLSName string
	// AllowHTTP will not setup :80, if TLS is nil and AllowHTTP is set,
	// no loadbalancer is created.
	AllowHTTP bool
	// The name of a Global Static IP. If specified, the IP associated with
	// this name is used in the Forwarding Rules for this loadbalancer.
	StaticIPName string

	// References to the generated GCP resources for this lB.
	Generated GCPResources
}

// TLSCerts encapsulates .pem encoded TLS information.
type TLSCerts struct {
	// Key is private key.
	Key string
	// Cert is a public key.
	Cert string
	// Chain is a certificate chain.
	Chain string
	Name  string
	// md5 hash(first 8 bytes) of the cert contents
	CertHash string
}

// GCPResources represents the resources created for this LB.
type GCPResources struct {
	// um is the UrlMap associated with this L7.
	um *compute.UrlMap
	// tp is the TargetHTTPProxy associated with this L7.
	tp *compute.TargetHttpProxy
	// tps is the TargetHTTPSProxy associated with this L7.
	tps *compute.TargetHttpsProxy
	// fw is the GlobalForwardingRule that points to the TargetHTTPProxy.
	fw *compute.ForwardingRule
	// fws is the GlobalForwardingRule that points to the TargetHTTPSProxy.
	fws *compute.ForwardingRule
	// ip is the static-ip associated with both GlobalForwardingRules.
	ip *compute.Address
	// sslCerts is the list of ssl certs associated with the targetHTTPSProxy.
	sslCerts []*compute.SslCertificate
	// oldSSLCerts is the list of certs that used to be hooked up to the
	// targetHTTPSProxy. We can't update a cert in place, so we need
	// to create - update - delete and storing the old certs in a list
	// prevents leakage if there's a failure along the way.
	oldSSLCerts []*compute.SslCertificate
}

func (l *L7s) edgeHop(lb *L7RuntimeInfo) error {
	if lb.AllowHTTP {
		if err := l.ensureHttp(); err != nil {
			return err
		}
	}
	// Defer promoting an ephemeral to a static IP until it's really needed.
	if lb.AllowHTTP && (l.runtimeInfo.TLS != nil || lb.TLSName != "") {
		glog.V(3).Infof("checking static ip for %v", l.Name)
		if err := l.checkStaticIP(); err != nil {
			return err
		}
	}
	if lb.TLS != nil || lb.TLSName != "" {
		glog.V(3).Infof("validating https for %v", l.Name)
		if err := l.ensureHttps(); err != nil {
			return err
		}
	}
	return nil
}

func (l *L7) ensureHttp() error {
	if err := l.ensureTargetHTTPProxy(); err != nil {
		return err
	}

	return l.checkHttpForwardingRule()
}

func (l *L7) ensureHttps() error {
	defer l.deleteOldSSLCerts()
	if err := l.checkSSLCert(); err != nil {
		return err
	}

	if len(l.sslCerts) == 0 {
		glog.V(3).Infof("No SSL certificates for %v, will not create HTTPS proxy.", l.Name)
		return nil
	}

	if err := l.ensureTargetHttpsProxy(); err != nil {
		return err
	}

	return l.checkHttpsForwardingRule()
}

// GetIP returns the ip associated with the forwarding rule for this l7.
func (l *L7RuntimeInfo) GetIP() string {
	if l.Generated.fw != nil {
		return l.fw.IPAddress
	}
	if l.Generated.fws != nil {
		return l.fws.IPAddress
	}
	return ""
}

// Cleanup deletes resources specific to this l7 in the right order.
// forwarding rule -> target proxy -> url map
// This leaves backends and health checks, which are shared across loadbalancers.
func (l *L7) Cleanup() error {
	if l.fw != nil {
		glog.V(2).Infof("Deleting global forwarding rule %v", l.fw.Name)
		if err := utils.IgnoreHTTPNotFound(l.cloud.DeleteGlobalForwardingRule(l.fw.Name)); err != nil {
			return err
		}
		l.fw = nil
	}
	if l.fws != nil {
		glog.V(2).Infof("Deleting global forwarding rule %v", l.fws.Name)
		if err := utils.IgnoreHTTPNotFound(l.cloud.DeleteGlobalForwardingRule(l.fws.Name)); err != nil {
			return err
		}
		l.fws = nil
	}
	if l.ip != nil {
		glog.V(2).Infof("Deleting static IP %v(%v)", l.ip.Name, l.ip.Address)
		if err := utils.IgnoreHTTPNotFound(l.cloud.DeleteGlobalAddress(l.ip.Name)); err != nil {
			return err
		}
		l.ip = nil
	}
	if l.tps != nil {
		glog.V(2).Infof("Deleting target https proxy %v", l.tps.Name)
		if err := utils.IgnoreHTTPNotFound(l.cloud.DeleteTargetHttpsProxy(l.tps.Name)); err != nil {
			return err
		}
		l.tps = nil
	}
	// Delete the SSL cert if it is from a secret, not referencing a pre-created GCE cert.
	if len(l.sslCerts) != 0 && l.runtimeInfo.TLSName == "" {
		var certErr error
		for _, cert := range l.sslCerts {
			glog.V(2).Infof("Deleting sslcert %s", cert.Name)
			if err := utils.IgnoreHTTPNotFound(l.cloud.DeleteSslCertificate(cert.Name)); err != nil {
				glog.Errorf("Old cert delete failed - %v", err)
				certErr = err
			}

		}
		l.sslCerts = nil
		if certErr != nil {
			return certErr
		}
	}
	if l.tp != nil {
		glog.V(2).Infof("Deleting target http proxy %v", l.tp.Name)
		if err := utils.IgnoreHTTPNotFound(l.cloud.DeleteTargetHttpProxy(l.tp.Name)); err != nil {
			return err
		}
		l.tp = nil
	}
	if l.um != nil {
		glog.V(2).Infof("Deleting url map %v", l.um.Name)
		if err := utils.IgnoreHTTPNotFound(l.cloud.DeleteUrlMap(l.um.Name)); err != nil {
			return err
		}
		l.um = nil
	}
	return nil
}

// GetLBAnnotations returns the annotations of an l7. This includes it's current status.
func GetLBAnnotations(l *L7RuntimeInfo, backendPool backends.BackendPool) (map[string]string, error) {
	status = map[string]string{}

	backends, err := getBackendNames(l.Generated.um)
	if err != nil {
		return nil, err
	}

	backendState := map[string]string{}
	for _, beName := range backends {
		backendState[beName] = backendPool.Status(beName)
	}
	jsonBackendState := "Unknown"
	b, err := json.Marshal(backendState)
	if err == nil {
		jsonBackendState = string(b)
	}
	certs := []string{}
	for _, cert := range l7.sslCerts {
		certs = append(certs, cert.Name)
	}

	status[fmt.Sprintf("%v/url-map", annotations.StatusPrefix)] = l.Generated.um.Name
	// Forwarding rule and target proxy might not exist if allowHTTP == false
	if l7.fw != nil {
		status[fmt.Sprintf("%v/forwarding-rule", annotations.StatusPrefix)] = l.Generated.fw.Name
	}
	if l7.tp != nil {
		status[fmt.Sprintf("%v/target-proxy", annotations.StatusPrefix)] = l.Generated.tp.Name
	}
	// HTTPs resources might not exist if TLS == nil
	if l7.fws != nil {
		status[fmt.Sprintf("%v/https-forwarding-rule", annotations.StatusPrefix)] = l.Generated.fws.Name
	}
	if l7.tps != nil {
		status[fmt.Sprintf("%v/https-target-proxy", annotations.StatusPrefix)] = l.Generated.tps.Name
	}
	if l7.ip != nil {
		status[fmt.Sprintf("%v/static-ip", annotations.StatusPrefix)] = l.Generated.ip.Name
	}
	if len(certs) > 0 {
		status[fmt.Sprintf("%v/ssl-cert", annotations.StatusPrefix)] = strings.Join(certs, ",")
	}
	// TODO: We really want to know *when* a backend flipped states.
	status[fmt.Sprintf("%v/backends", annotations.StatusPrefix)] = jsonBackendState
	return status, nil
}
