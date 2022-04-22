package k8s

import (
	"context"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	podKey   = "enforce.k8s.io"
	podValue = "deny-third-party-execution"
)

// GetNewPods is used to get information about pods.
func GetNewPods(pods map[string]*v1.Pod, nodeName, kubeconfig string) {
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
