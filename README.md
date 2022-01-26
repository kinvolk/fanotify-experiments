# fanotify PoC

This PoC aims to take a container rootfs and only allows access to files in it if they're signed with a particular public key.

For now it prints hashes of files accessed

## Usage

```console
sudo ./fanotify-poc ROOTFS_PATH
```

## Caveats

Fanotify doesn't work across mount namespaces so this only works for files accessed from outside the container.
