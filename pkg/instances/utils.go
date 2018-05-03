package instances

import (
	compute "google.golang.org/api/compute/v1"

	"k8s.io/ingress-gce/pkg/utils"
)

// Helper method to create instance groups.
// This method exists to ensure that we are using the same logic at all places.
func EnsureInstanceGroupsAndPorts(nodePool NodePool, namer *utils.Namer, ports []int64) ([]*compute.InstanceGroup, error) {
	return nodePool.EnsureInstanceGroupsAndPorts(namer.InstanceGroup(), ports)
}

func instanceNamesFromRefs(refs []*compute.InstanceReference) ([]string, error) {
	var names []string
	for _, r := range refs {
		name, err := utils.ResourceName(r.Instance)
		if err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}
