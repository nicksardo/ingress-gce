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
	"net/http"

	"github.com/golang/glog"
	compute "google.golang.org/api/compute/v1"
	"k8s.io/ingress-gce/pkg/utils"
)

// checkStaticIP reserves a static IP allocated to the Forwarding Rule.
func (l *L7s) checkStaticIP(lb *L7RuntimeInfo) (err error) {
	if l.fw == nil || l.fw.IPAddress == "" {
		return fmt.Errorf("will not create static IP without a forwarding rule")
	}
	// Don't manage staticIPs if the user has specified an IP.
	if address, manageStaticIP := l.getEffectiveIP(); !manageStaticIP {
		glog.V(3).Infof("Not managing user specified static IP %v", address)
		return nil
	}
	staticIPName := l.namer.ForwardingRule(l.Name, utils.HTTPProtocol)
	ip, _ := l.cloud.GetGlobalAddress(staticIPName)
	if ip == nil {
		glog.V(3).Infof("Creating static ip %v", staticIPName)
		err = l.cloud.ReserveGlobalAddress(&compute.Address{Name: staticIPName, Address: l.fw.IPAddress})
		if err != nil {
			if utils.IsHTTPErrorCode(err, http.StatusConflict) ||
				utils.IsHTTPErrorCode(err, http.StatusBadRequest) {
				glog.V(3).Infof("IP %v(%v) is already reserved, assuming it is OK to use.",
					l.fw.IPAddress, staticIPName)
				return nil
			}
			return err
		}
		ip, err = l.cloud.GetGlobalAddress(staticIPName)
		if err != nil {
			return err
		}
	}
	l.ip = ip
	return nil
}

func (l *L7s) ensureAddress(lb *L7RuntimeInfo) error {
	addrName := l.namer.ForwardingRule(l.Name, utils.HTTPProtocol)
	address, err := l.cloud.GetGlobalAddress(addrName)
	if err != nil && !utils.IsHTTPErrorCode(err, http.StatusNotFound) {
		return err
	}

	// TODO: how to determine IP
	ip := ""

	if address != nil {
		lb.Generated.ip = address
		return nil
	}

	glog.V(3).Infof("Creating static ip %v", staticIPName)
	err = l.cloud.ReserveGlobalAddress(&compute.Address{
		Name:    addrName,
		Address: ip,
	})
	if err != nil {
		return err
	}

	address, err = l.cloud.GetGlobalAddress(addrName)
	if err != nil && !utils.IsHTTPErrorCode(err, http.StatusNotFound) {
		return err
	}

	lb.Generated.ip = address
	return nil
}

// getEffectiveIP returns a string with the IP to use in the HTTP and HTTPS
// forwarding rules, and a boolean indicating if this is an IP the controller
// should manage or not.
func (l *L7) getEffectiveIP() (string, bool) {

	// A note on IP management:
	// User specifies a different IP on startup:
	//	- We create a forwarding rule with the given IP.
	//		- If this ip doesn't exist in GCE, we create another one in the hope
	//		  that they will rectify it later on.
	//	- In the happy case, no static ip is created or deleted by this controller.
	// Controller allocates a staticIP/ephemeralIP, but user changes it:
	//  - We still delete the old static IP, but only when we tear down the
	//	  Ingress in Cleanup(). Till then the static IP stays around, but
	//    the forwarding rules get deleted/created with the new IP.
	//  - There will be a period of downtime as we flip IPs.
	// User specifies the same static IP to 2 Ingresses:
	//  - GCE will throw a 400, and the controller will keep trying to use
	//    the IP in the hope that the user manually resolves the conflict
	//    or deletes/modifies the Ingress.
	// TODO: Handle the last case better.

	if l.runtimeInfo.StaticIPName != "" {
		// Existing static IPs allocated to forwarding rules will get orphaned
		// till the Ingress is torn down.
		if ip, err := l.cloud.GetGlobalAddress(l.runtimeInfo.StaticIPName); err != nil || ip == nil {
			glog.Warningf("The given static IP name %v doesn't translate to an existing global static IP, ignoring it and allocating a new IP: %v",
				l.runtimeInfo.StaticIPName, err)
		} else {
			return ip.Address, false
		}
	}
	if l.ip != nil {
		return l.ip.Address, true
	}
	return "", true
}
