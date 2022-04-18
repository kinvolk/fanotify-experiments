package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/oci"
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
	"github.com/s3rj1k/go-fanotify/fanotify"
	log "github.com/sirupsen/logrus"
)

const (
	podKey   = "enforce.k8s.io"
	podValue = "deny-third-party-execution"
)

func init() {
	log.SetLevel(log.DebugLevel)

	// Name of the node in k8s control plane.
	hostname = os.Getenv("HOSTNAME")
	if hostname == "" {
		log.Fatal("HOSTNAME not specified")
	}

	log.Debugf("Using hostname: %s", hostname)

	hostRuntime = runtime(os.Getenv("RUNTIME"))
	if hostRuntime == "" {
		log.Fatal("RUNTIME not specified")
	}

	switch hostRuntime {
	case runtimeContainerd:
		containerdNamespace = "k8s.io"
	case runtimeDocker:
		containerdNamespace = "moby"
	default:
		log.Fatalf("Unsupported runtime %s provided. Supported runtimes: %s, %s.", hostRuntime, runtimeDocker, runtimeContainerd)
	}

	log.Debugf("Using runtime: %s", hostRuntime)

	kubeconfig = os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		log.Fatal("KUBECONFIG not specified")
	}

	log.Debugf("Using kubeconfig: %s", kubeconfig)
}

type runtime string

var (
	hostname            string
	hostRuntime         runtime
	containerdNamespace string
	kubeconfig          string
)

const (
	runtimeDocker     = runtime("docker")
	runtimeContainerd = runtime("containerd")
	containerdSocket  = "/run/containerd/containerd.sock"
)

type Container struct {
	*pb.ContainerDefinition
	*oci.Spec
}

type ContainerNotifier struct {
	notifyFD   *fanotify.NotifyFD
	cnt        *Container
	firstEvent bool
	sha256Sums map[string]string
	rootFSPath string
}

func getContainer(cntIG *pb.ContainerDefinition, oci *oci.Spec) *Container {
	return &Container{
		cntIG, oci,
	}
}

func getContainerFromID(id string) (containerd.Container, func(), error) {
	client, err := containerd.New(containerdSocket, containerd.WithDefaultNamespace(containerdNamespace))
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

func getOCISpec(cntID string) (*oci.Spec, error) {
	cnt, closer, err := getContainerFromID(cntID)
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

func NewContainerNotifier(cntIG *pb.ContainerDefinition) (*ContainerNotifier, error) {
	oci, err := getOCISpec(cntIG.Id)
	if err != nil {
		return nil, fmt.Errorf("getting containerd definition of container: %v", err)
	}

	cnt := getContainer(cntIG, oci)

	fanotifyFlags := uint(unix.FAN_CLASS_CONTENT | unix.FAN_UNLIMITED_QUEUE | unix.FAN_UNLIMITED_MARKS)
	openFlags := os.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC

	containerNotify, err := fanotify.Initialize(fanotifyFlags, openFlags)
	if err != nil {
		return nil, err
	}

	n := &ContainerNotifier{
		cnt:        cnt,
		firstEvent: true,
		sha256Sums: make(map[string]string),
		notifyFD:   containerNotify,

		// This path looks something like this:
		// /proc/49190/root
		rootFSPath: filepath.Join("/proc", fmt.Sprintf("%d", cnt.Pid), "root"),
	}

	markFolders := []string{n.rootFSPath}
	markFiles := []string{}

	for _, mnt := range cnt.Mounts {
		// Ignore list
		switch mnt.Destination {
		case "/dev/shm", "/var/run/secrets/kubernetes.io/serviceaccount":
			continue

		case "/etc/resolv.conf", "/etc/hostname", "/etc/hosts", "/dev/termination-log":
			markFiles = append(markFiles, mnt.Source)
			continue
		}

		// Also mark the host mounted dirs.
		if mnt.Type == "bind" {
			markFolders = append(markFolders, mnt.Source)
		}
	}

	if err := n.markDirs(markFolders); err != nil {
		return nil, fmt.Errorf("marking dirs: %w", err)
	}

	if err := n.markFiles(markFiles); err != nil {
		return nil, fmt.Errorf("marking files: %w", err)
	}

	return n, nil
}

func (n *ContainerNotifier) markDirs(paths []string) error {
	for _, path := range paths {
		err := n.notifyFD.Mark(unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, unix.FAN_OPEN_EXEC_PERM|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, path)
		if err != nil {
			n.notifyFD.File.Close()
			log.Errorf("Marking %q: %s", path, err)
			return err
		}

		log.Infof("Marking %q: done", path)
	}

	return nil
}

func (n *ContainerNotifier) markFiles(paths []string) error {
	for _, path := range paths {
		err := n.notifyFD.Mark(unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, path)
		if err != nil {
			n.notifyFD.File.Close()
			log.Errorf("Marking %q: %s", path, err)
			return err
		}

		log.Infof("Marking %q: done", path)
	}

	return nil
}

// path looks like this: /proc/49190/root/usr/bin/touch
func (n *ContainerNotifier) ignoreMountPath(path string) bool {
	// Here the path looks like: /usr/bin/touch
	path = strings.TrimPrefix(path, n.rootFSPath)

	for _, mnt := range n.cnt.Mounts {
		// Check if the path starts with one of the mount paths.
		if strings.HasPrefix(path, mnt.Destination) {
			return true
		}
	}

	return false
}

func (n *ContainerNotifier) handleEvent() (bool, error) {
	// This is a blocking call.
	data, err := n.notifyFD.GetEvent(os.Getpid())
	if err != nil {
		return true, fmt.Errorf("getting event: %w", err)
	}

	if data == nil {
		return false, nil
	}

	defer data.Close()

	// TODO: What if the container was already started, so any modifications done to the container FS won't be encountered here.
	if n.firstEvent {
		log.Infof("first notification received, walking over %s", n.rootFSPath)

		// Make a list of all the executables in the rootfs and create a map of file path and its SHA256
		// store this map in the object.
		// NOTE: If there is no trailing front slash then this function does not walk on the dir.
		err := filepath.WalkDir(n.rootFSPath+"/",
			func(path string, dirEntry os.DirEntry, err error) error {
				if err != nil && os.IsNotExist(err) {
					return nil
				} else if err != nil {
					return fmt.Errorf("default error: %v", err)
				}

				// Figure out if the file is not a dir.
				// Calculate its SHA256sum.
				if dirEntry.IsDir() {
					return nil
				}

				info, err := dirEntry.Info()
				if err != nil && os.IsNotExist(err) {
					return nil
				} else if err != nil {
					return fmt.Errorf("getting info: %w", err)
				}

				// Ignore the mounted volumes checks.
				if n.ignoreMountPath(path) {
					return nil
				}

				// Ignore sym-links.
				if info.Mode()&fs.ModeSymlink != 0 {
					return nil
				}

				// Check if the file is neither user executabe (0100) nor group executable (0010) nor other executable (0001).
				// We don't have any concern for non-executables.
				if !(info.Mode()&0100 != 0 || info.Mode()&0010 != 0 || info.Mode()&0001 != 0) {
					return nil
				}

				sha256sum, err := calculateSHA256Sum(path)
				if err != nil {
					return fmt.Errorf("calculating sha256sum of %s: %w", path, err)
				}

				n.sha256Sums[path] = sha256sum

				return nil
			})
		if err != nil {
			return false, fmt.Errorf("walking the container rootfs: %w", err)
		}

		n.firstEvent = false
	}

	// The path will look like this:
	// /usr/bin/touch
	path, err := data.GetPath()
	if err != nil {
		log.Errorf("getting file path: %v", err)
		n.notifyFD.ResponseDeny(data)
		return false, nil
	}

	// This will look something like this:
	// /proc/49190/root/usr/bin/touch
	path = filepath.Join(n.rootFSPath, path)

	currentSum, err := calculateSHA256SumWithFileObject(data.File())
	if err != nil {
		log.Errorf("calculating sha256sum of %s: %v", path, err)
		log.Infof("[DENY]:%s: %s", n.cnt.Id, path)
		n.notifyFD.ResponseDeny(data)
		return false, nil
	}

	predeterminedSum, ok := n.sha256Sums[path]
	if !ok {
		// This means it is a new file that is called for execution so deny it.
		log.Infof("[DENY]:%s: %s", n.cnt.Id, path)
		n.notifyFD.ResponseDeny(data)
		return false, nil
	}

	if predeterminedSum != currentSum {
		// This means that the file was modified.
		log.Infof("[DENY]:%s: %s", n.cnt.Id, path)
		n.notifyFD.ResponseDeny(data)
		return false, nil
	}

	log.Infof("[ALLOW]:%s: %s", n.cnt.Id, path)
	n.notifyFD.ResponseAllow(data)
	return false, nil
}

func watchContainerFANotifyEvents(notifier *ContainerNotifier) {
	for {
		stop, err := notifier.handleEvent()
		if err != nil {
			log.Errorf("error handling event: %v", err)
		}

		if stop {
			notifier.notifyFD.File.Close()
			return
		}

	}
}

func getNewPods(pods map[string]*v1.Pod, nodeName string) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatalf("building config from flags: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("creating clientset: %v", err)
	}

	ctx := context.Background()
	watcher, err := clientset.CoreV1().Pods("").Watch(ctx, metav1.ListOptions{
		LabelSelector: podKey + "=" + podValue,
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		log.Fatalf("getting watcher on pods: %v", err)
	}

	ch := watcher.ResultChan()

	for {
		event := <-ch

		pod, ok := event.Object.(*v1.Pod)
		if !ok {
			// When we hit the "too many open files error" at that point this stops working and we start getting nil objects.
			log.Fatalf("received an object which is not a pod: %#v", event.Object)
			continue
		}

		for _, cnt := range pod.Spec.Containers {
			// A typical container name looks like this: k8s_fedora_fedora_kube-system_8143ee7d-d615-4c8e-9b1b-3af20fad49b1_2
			id := "k8s_" + pod.Name + "_" + cnt.Name + "_" + pod.Namespace + "_" + string(pod.UID)

			switch event.Type {
			case watch.Added:
				log.Debugf("got a new container, adding to the list: %s", id)
				pods[id] = pod
			case watch.Modified:
				log.Debugf("got an existing container, updating the list: %s", id)
				pods[id] = pod
			case watch.Deleted:
				log.Debugf("removing the container from the list: %s", id)
				delete(pods, id)
			}
		}
	}
}

func getContainerName(cnt pb.ContainerDefinition) (string, error) {
	if hostRuntime == runtimeDocker {
		cntName := cnt.Name
		// The list has names saved without the restart count like this:
		// k8s_fedora_fedora_kube-system_8143ee7d-d615-4c8e-9b1b-3af20fad49b1
		// but the containers are named as k8s_fedora_fedora_kube-system_8143ee7d-d615-4c8e-9b1b-3af20fad49b1_2
		return cntName[:strings.LastIndex(cntName, "_")], nil
	}

	// From here it is assumed that the container runtime is containerd.

	// Talk to the containerd API and get the container.
	c, closer, err := getContainerFromID(cnt.Id)
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

func main() {
	pods := make(map[string]*v1.Pod)
	go getNewPods(pods, hostname)

	fanotifyFDs := make(map[string]*ContainerNotifier)

	handleContainerEvents := func(event pubsub.PubSubEvent) {
		go func() {
			cid := event.Container.Id
			cnt := event.Container

			cntName, err := getContainerName(cnt)
			if err != nil {
				log.Errorf("getting container name: %v", err)
				return
			}

			// Ignore list.
			// This is a pause container.
			if strings.HasPrefix(cntName, "k8s_POD_") {
				return
			}

			// Sometimes the container can take time to be available.
			var retryInterval = time.Second * 1
			var timeout = time.Minute * 1
			if err := wait.PollImmediate(retryInterval, timeout, func() (done bool, err error) {
				_, ok := pods[cntName]
				if !ok {
					// This means that this is not the target container with our required labels.
					log.Debugf("given container with prefix not found in the k8s list: %s", cntName)
					return false, nil
				}

				return true, nil
			}); err != nil {
				log.Debugf("ignoring container: %s", cntName)
				return
			}

			switch event.Type {
			case pubsub.EventTypeAddContainer:
				notifier, err := NewContainerNotifier(&cnt)
				if err != nil {
					log.Fatalf("creating notifier: %v\n", err)
				}

				fanotifyFDs[cid] = notifier

				log.Infof("container started: %v", cid)
				// TODO: Create a signal associated with this go routine to stop the go routine.
				go watchContainerFANotifyEvents(notifier)

			case pubsub.EventTypeRemoveContainer:
				log.Infof("container stopped: %v", cid)
				notifier := fanotifyFDs[cid]
				notifier.notifyFD.File.Close()
				unix.Close(notifier.notifyFD.Fd)
				delete(fanotifyFDs, cid)
			}
		}()
	}

	cc := containercollection.ContainerCollection{}
	withFuncs := []containercollection.ContainerCollectionOption{
		containercollection.WithRuncFanotify(),
		containercollection.WithPubSub([]pubsub.FuncNotify{handleContainerEvents}...),
	}

	if hostRuntime == runtimeDocker {
		withFuncs = append(withFuncs, containercollection.WithDockerEnrichment())
	}

	if err := cc.ContainerCollectionInitialize(withFuncs...); err != nil {
		log.Fatalf("initializing container collection: %v", err)
	}

	log.Infoln("Waiting for containers to start")
	log.Infoln("Stop the process using Ctrl + C")

	exitSignal := make(chan os.Signal)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal
}

func calculateSHA256Sum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	return calculateSHA256SumWithFileObject(f)
}

func calculateSHA256SumWithFileObject(f *os.File) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("copying data: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
