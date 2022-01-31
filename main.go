package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"os"

	"github.com/s3rj1k/go-fanotify/fanotify"
)

type ContainerNotifier struct {
	N *fanotify.NotifyFD
}

func NewContainerNotifier(filePath string) (*ContainerNotifier, error) {
	n := &ContainerNotifier{}

	fanotifyFlags := uint(unix.FAN_CLASS_CONTENT | unix.FAN_UNLIMITED_QUEUE | unix.FAN_UNLIMITED_MARKS)
	openFlags := os.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC

	containerNotify, err := fanotify.Initialize(fanotifyFlags, openFlags)
	if err != nil {
		return nil, err
	}
	n.N = containerNotify

	err = containerNotify.Mark(unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, filePath)
	if err != nil {
		log.Printf("Marking %q: %s", filePath, err)
	} else {
		log.Printf("Marking %q: done", filePath)
	}

	return n, nil
}

func (n *ContainerNotifier) handleEvent(data *fanotify.EventMetadata) {
	if data == nil {
		return
	}

	defer data.Close()

	path, err := data.GetPath()
	if err != nil {
		log.Fatalf("Couldn't get path")
	}

	dataFile := data.File()
	defer dataFile.Close()

	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("Errorz: %v", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatalf("Errorz: %v", err)
	}

	hashString := hex.EncodeToString(h.Sum(nil))

	if hashString == "d0b909b12e97eaf02285fe7962d2f5490ce165377b8fdf77faa2db517fc97f61" {
		fmt.Printf("[ALLOWED] ")
		n.N.ResponseAllow(data)
	} else {
		fmt.Printf("[DENIED] ")
		n.N.ResponseDeny(data)
	}

	fmt.Printf("file %q hash %s\n", path, hashString)
}

func main() {
	notifier, err := NewContainerNotifier(os.Args[1])
	if err != nil {
		log.Fatalf("Error creating notifier: %v\n", err)
	}

	for {
		data, err := notifier.N.GetEvent(os.Getpid())
		if err != nil {
			log.Fatalf("Error getting event: %v\n", err)
		}

		go notifier.handleEvent(data)
	}
}
