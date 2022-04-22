// Package cmd has code for all the commands of fanotify-mon.
package cmd

import (
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kinvolk/fanotify-poc/internal"
	"github.com/kinvolk/fanotify-poc/pkg/containerd"
	"github.com/kinvolk/fanotify-poc/pkg/docker"
	"github.com/kinvolk/fanotify-poc/pkg/k8s"
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

var (
	hostname    string
	hostRuntime string
	kubeconfig  string
)

var RootCmd = &cobra.Command{
	Use:   "fanotify-mon",
	Short: "Monitor for fanotify",
	Run: func(cmd *cobra.Command, args []string) {
		fanotify(hostname, hostRuntime, kubeconfig)
	},
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	log.SetLevel(log.DebugLevel)
	RootCmd.DisableAutoGenTag = true

	pf := RootCmd.PersistentFlags()
	pf.StringVarP(&hostname, "hostname", "", "", "Name of node in which fanotify-mon binary is running")
	pf.StringVarP(&hostRuntime, "runtime", "", "docker", "Name of k8s container runtime")
	pf.StringVarP(&kubeconfig, "kubeconfig", "", "$HOME/.kube/config", "Path to kubeconfig")
	containerd.SetContainerdNamespace(hostRuntime)
}

func fanotify(hostname, hostRuntime, kubeconfig string) {
	pods := make(map[string]*v1.Pod)
	go k8s.GetNewPods(pods, hostname, kubeconfig)

	fanotifyFDs := make(map[string]*internal.ContainerNotifier)

	handleContainerEvents := func(event pubsub.PubSubEvent) {
		go func() {
			cid := event.Container.Id
			cnt := event.Container

			cntName, err := containerd.GetContainerName(cnt, hostRuntime)
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
				notifier, err := internal.NewContainerNotifier(&cnt)
				if err != nil {
					log.Fatalf("creating notifier: %v\n", err)
				}

				fanotifyFDs[cid] = notifier

				log.Infof("container started: %v", cid)
				// TODO: Create a signal associated with this go routine to stop the go routine.
				go internal.WatchContainerFANotifyEvents(notifier)

			case pubsub.EventTypeRemoveContainer:
				log.Infof("container stopped: %v", cid)
				notifier := fanotifyFDs[cid]
				notifier.NotifyFD.File.Close()
				unix.Close(notifier.NotifyFD.Fd)
				delete(fanotifyFDs, cid)
			}
		}()
	}

	cc := containercollection.ContainerCollection{}
	withFuncs := []containercollection.ContainerCollectionOption{
		containercollection.WithRuncFanotify(),
		containercollection.WithPubSub([]pubsub.FuncNotify{handleContainerEvents}...),
	}

	if hostRuntime == docker.RuntimeDocker {
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
