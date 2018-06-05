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
	"fmt"

	"github.com/golang/glog"
	compute "google.golang.org/api/compute/v1"
	"k8s.io/ingress-gce/pkg/utils"
)

func (l *L7s) checkHttpForwardingRule() error {
	if l.tp == nil {
		return fmt.Errorf("cannot create forwarding rule without proxy")
	}
	name := l.namer.ForwardingRule(l.Name, utils.HTTPProtocol)
	address, _ := l.getEffectiveIP()
	fw, err := l.checkForwardingRule(name, l.tp.SelfLink, address, httpDefaultPortRange)
	if err != nil {
		return err
	}
	l.fw = fw
	return nil
}

func (l *L7) checkHttpsForwardingRule() error {
	if l.tps == nil {
		glog.V(3).Infof("No https target proxy for %v, not created https forwarding rule", l.Name)
		return nil
	}
	name := l.namer.ForwardingRule(l.Name, utils.HTTPSProtocol)
	address, _ := l.getEffectiveIP()
	fws, err := l.checkForwardingRule(name, l.tps.SelfLink, address, httpsDefaultPortRange)
	if err != nil {
		return err
	}
	l.fws = fws
	return nil
}

func (l *L7) ensureForwardingRule(name, proxyLink, ip, portRange string) (fw *compute.ForwardingRule, err error) {
	fw, err = l.cloud.GetGlobalForwardingRule(name)
	if utils.IgnoreHTTPNotFound(err) != nil {
		return nil, err
	}

	if fw != nil && (ip != "" && fw.IPAddress != ip || fw.PortRange != portRange) {
		glog.Warningf("Recreating forwarding rule %v(%v), so it has %v(%v)",
			fw.IPAddress, fw.PortRange, ip, portRange)
		if err = utils.IgnoreHTTPNotFound(l.cloud.DeleteGlobalForwardingRule(name)); err != nil {
			return nil, err
		}
		fw = nil
	}
	if fw == nil {
		glog.V(3).Infof("Creating forwarding rule for proxy %q and ip %v:%v", proxyLink, ip, portRange)
		rule := &compute.ForwardingRule{
			Name:       name,
			IPAddress:  ip,
			Target:     proxyLink,
			PortRange:  portRange,
			IPProtocol: "TCP",
		}
		if err = l.cloud.CreateGlobalForwardingRule(rule); err != nil {
			return nil, err
		}
		fw, err = l.cloud.GetGlobalForwardingRule(name)
		if err != nil {
			return nil, err
		}
	}
	// TODO: If the port range and protocol don't match, recreate the rule
	if utils.CompareLinks(fw.Target, proxyLink) {
		glog.V(4).Infof("Forwarding rule %v already exists", fw.Name)
	} else {
		glog.V(3).Infof("Forwarding rule %v has the wrong proxy, setting %v overwriting %v",
			fw.Name, fw.Target, proxyLink)
		if err := l.cloud.SetProxyForGlobalForwardingRule(fw.Name, proxyLink); err != nil {
			return nil, err
		}
	}
	return fw, nil
}
