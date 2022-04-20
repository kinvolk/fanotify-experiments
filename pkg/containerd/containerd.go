package containerd

import (
	"context"
	"fmt"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/oci"
	"github.com/kinvolk/fanotify-poc/pkg/docker"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	log "github.com/sirupsen/logrus"
)

const (
	ContainerdSocket  = "/run/containerd/containerd.sock"
	RuntimeContainerd = "containerd"
)

var ContainerdNamespace string

func SetContainerdNamespace(hostRuntime string) {
	switch hostRuntime {
	case RuntimeContainerd:
		ContainerdNamespace = "k8s.io"
	case docker.RuntimeDocker:
		ContainerdNamespace = "moby"
	default:
		log.Fatalf("Unsupported runtime %s provided. Supported runtimes: %s, %s.", hostRuntime, docker.RuntimeDocker, RuntimeContainerd)
	}
}

func GetContainerFromID(id, containerdNamespace string) (containerd.Container, func(), error) {
	client, err := containerd.New(ContainerdSocket, containerd.WithDefaultNamespace(containerdNamespace))
	if err != nil {
		return nil, func() {}, fmt.Errorf("creating containerd client: %w", err)
	}

	closer := func() {
		client.Close()
	}

	ctx := context.Background()

	cnts, err := client.Containers(ctx, "id=="+id)
	if err != nil {
		return nil, closer, fmt.Errorf("listing containers: %w", err)
	}

	if len(cnts) == 0 {
		return nil, closer, fmt.Errorf("no container found")
	}

	return cnts[0], closer, nil

}

func GetOCISpec(cntID, containerdNamespace string) (*oci.Spec, error) {
	cnt, closer, err := GetContainerFromID(cntID, containerdNamespace)
	defer closer()
	if err != nil {
		return nil, fmt.Errorf("getting container from id: %w", err)
	}

	cntSpec, err := cnt.Spec(context.Background())
	if err != nil {
		return nil, fmt.Errorf("getting container spec: %w", err)
	}

	return cntSpec, nil
}

func GetContainerName(cnt pb.ContainerDefinition, hostRuntime string) (string, error) {
	if hostRuntime == docker.RuntimeDocker {
		cntName := cnt.Name
		// The list has names saved without the restart count like this:
		// k8s_fedora_fedora_kube-system_8143ee7d-d615-4c8e-9b1b-3af20fad49b1
		// but the containers are named as k8s_fedora_fedora_kube-system_8143ee7d-d615-4c8e-9b1b-3af20fad49b1_2
		return cntName[:strings.LastIndex(cntName, "_")], nil
	}

	// From here it is assumed that the container runtime is containerd.

	// Talk to the containerd API and get the container.
	c, closer, err := GetContainerFromID(cnt.Id, ContainerdNamespace)
	defer closer()
	if err != nil {
		return "", fmt.Errorf("getting container from id: %w", err)
	}

	ctx := context.Background()
	container, err := c.Info(ctx)
	if err != nil {
		return "", fmt.Errorf("getting container info: %w", err)
	}

	// Generate the name in the same fashion as the docker using the labels.
	var podName string

	switch container.Labels["io.cri-containerd.kind"] {
	case "sandbox":
		podName = "POD"
	case "container":
		podName = container.Labels["io.kubernetes.pod.name"]
	default:
		return "", fmt.Errorf("no kind label on container")
	}

	cntName := container.Labels["io.kubernetes.container.name"]
	podNamespace := container.Labels["io.kubernetes.pod.namespace"]
	podUID := container.Labels["io.kubernetes.pod.uid"]

	return "k8s_" + podName + "_" + cntName + "_" + podNamespace + "_" + podUID, nil
}
