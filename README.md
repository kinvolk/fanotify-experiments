# fanotify PoC

This PoC aims to take a container rootfs and only allows access to files in it if they're signed with a particular public key.

For now it prints hashes of files accessed

## Usage

```console
sudo ./fanotify-poc ROOTFS_PATH
```

## Caveats

Fanotify doesn't work across mount namespaces so this only works for files accessed from outside the container.


## Testing go binary

- Build the binary from this code: `make build`.
- Run the binary as root `sudo ./fanotify-mon --hostname="yourhost" --runtime=docker --kubeconfig="kubeconfig path"`
- Now start pods so that this application will start monitoring:

```
kubectl run --image nginx -l enforce.k8s.io=deny-third-party-execution nginx
```

- Once the pod starts exec into it and test the following:

```bash
touch newfile
ls

rm -rf /usr/bin/touch
cat <<EOF > /usr/bin/touch
#!/bin/bash

echo this is a new touch
EOF

chmod +x /usr/bin/touch
touch file
```

- The last execution of `touch` should be blocked and you should see error: `Operation not permitted`. Also the running `./fanotify-mon` will show you what was denied in its logs.
- You can see logs of the containerd process also using `sudo journalctl -fu containerd`.
