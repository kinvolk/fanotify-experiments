# fanotify C PoC

This PoC takes a container and detects files executed by it, printing stat information.

## Usage

```console
PID=<PID 1 in the container>

sudo ./fanotify_example /proc/$PID/ns/mnt /proc/$PID/ns/pid /
```
