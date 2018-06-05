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
	"net/http"

	"github.com/golang/glog"
	"k8s.io/ingress-gce/pkg/utils"
)

func (l *L7s) ensureComputeUrlMap(ri *L7RuntimeInfo) error {
	// Every update replaces the entire urlmap.
	expectedMap := ToComputeURLMap(ri.Name, ri.UrlMap, l.namer)

	currentMap, err := l.cloud.GetUrlMap(l.um.Name)
	if err != nil && !utils.IsHTTPErrorCode(err, http.StatusNotFound) {
		return err
	}

	if currentMap == nil {
		glog.V(3).Infof("Creating URLMap %q", expectedMap.Name)
		if err := l.cloud.CreateUrlMap(expectedMap); err != nil {
			return err
		}
		l.um = currentMap
		return nil
	}

	if mapsEqual(currentMap, expectedMap) {
		glog.V(4).Infof("URLMap for %q is unchanged", l.Name)
		return nil
	}

	glog.V(3).Infof("Updating URLMap: %q", l.um.Name)
	if err := l.cloud.UpdateUrlMap(expectedMap); err != nil {
		return err
	}

	l.um = expectedMap
	return nil
}
