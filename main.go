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

	// unix.FAN_OPEN_PERM is what we want but we need to add a goroutine so it
	// handles us opening the file to generate the hash
	err = containerNotify.Mark(unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, unix.FAN_OPEN, unix.AT_FDCWD, filePath)
	if err != nil {
		log.Printf("Marking %q: %s", filePath, err)
	} else {
		log.Printf("Marking %q: done", filePath)
	}

	return n, nil
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

		if data == nil {
			continue
		}

		dataFile := data.File()

		path, err := data.GetPath()
		if err != nil {
			log.Fatalf("Couldn't get path")
		}

		f, err := os.Open(path)
		if err != nil {
			log.Fatalf("Errorz: %v", err)
		}

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			log.Fatalf("Errorz: %v", err)
		}
		f.Close()

		notifier.N.ResponseAllow(data)

		dataFile.Close()
		data.Close()

		fmt.Printf("file %q hash %s\n", path, hex.EncodeToString(h.Sum(nil)))
	}
}
