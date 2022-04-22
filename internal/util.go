// Package internal contains the utility functions used across the codebase.
package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/oci"
	"github.com/kinvolk/fanotify-poc/pkg/containerd"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/s3rj1k/go-fanotify/fanotify"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type Container struct {
	*pb.ContainerDefinition
	*oci.Spec
}

type ContainerNotifier struct {
	NotifyFD   *fanotify.NotifyFD
	cnt        *Container
	firstEvent bool
	sha256Sums map[string]string
	rootFSPath string
}

func (n *ContainerNotifier) markDirs(paths []string) error {
	for _, path := range paths {
		err := n.NotifyFD.Mark(unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, unix.FAN_OPEN_EXEC_PERM|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, path)
		if err != nil {
			n.NotifyFD.File.Close()
			log.Errorf("Marking %q: %s", path, err)
			return err
		}

		log.Infof("Marking %q: done", path)
	}

	return nil
}

func (n *ContainerNotifier) markFiles(paths []string) error {
	for _, path := range paths {
		err := n.NotifyFD.Mark(unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, path)
		if err != nil {
			n.NotifyFD.File.Close()
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
	data, err := n.NotifyFD.GetEvent(os.Getpid())
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
		n.NotifyFD.ResponseDeny(data)
		return false, nil
	}

	// This will look something like this:
	// /proc/49190/root/usr/bin/touch
	path = filepath.Join(n.rootFSPath, path)

	currentSum, err := calculateSHA256SumWithFileObject(data.File())
	if err != nil {
		log.Errorf("calculating sha256sum of %s: %v", path, err)
		log.Infof("[DENY]:%s: %s", n.cnt.Id, path)
		n.NotifyFD.ResponseDeny(data)
		return false, nil
	}

	predeterminedSum, ok := n.sha256Sums[path]
	if !ok {
		// This means it is a new file that is called for execution so deny it.
		log.Infof("[DENY]:%s: %s", n.cnt.Id, path)
		n.NotifyFD.ResponseDeny(data)
		return false, nil
	}

	if predeterminedSum != currentSum {
		// This means that the file was modified.
		log.Infof("[DENY]:%s: %s", n.cnt.Id, path)
		n.NotifyFD.ResponseDeny(data)
		return false, nil
	}

	log.Infof("[ALLOW]:%s: %s", n.cnt.Id, path)
	n.NotifyFD.ResponseAllow(data)
	return false, nil
}

func WatchContainerFANotifyEvents(notifier *ContainerNotifier) {
	for {
		stop, err := notifier.handleEvent()
		if err != nil {
			log.Errorf("error handling event: %v", err)
		}

		if stop {
			notifier.NotifyFD.File.Close()
			return
		}

	}
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

func NewContainerNotifier(cntIG *pb.ContainerDefinition) (*ContainerNotifier, error) {
	oci, err := containerd.GetOCISpec(cntIG.Id, containerd.ContainerdNamespace)
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
		NotifyFD:   containerNotify,

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

func getContainer(cntIG *pb.ContainerDefinition, oci *oci.Spec) *Container {
	return &Container{
		cntIG, oci,
	}
}
