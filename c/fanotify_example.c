#define _GNU_SOURCE     /* Needed to get O_LARGEFILE definition */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fanotify.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Read all available fanotify events from the file descriptor 'fd'. */

static void
handle_events(int fd)
{
    const struct fanotify_event_metadata *metadata;
    struct fanotify_event_metadata buf[200];
    ssize_t len;
    char path[PATH_MAX];
    ssize_t path_len;
    char procfd_path[PATH_MAX];
    struct fanotify_response response;

    /* Loop while events can be read from fanotify file descriptor. */

    for (;;) {

        /* Read some events. */

        len = read(fd, buf, sizeof(buf));
        if (len == -1 && errno != EAGAIN) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        /* Check if end of available data reached. */

        if (len <= 0)
            break;

        /* Point to the first event in the buffer. */

        metadata = buf;

        /* Loop over all events in the buffer. */

        while (FAN_EVENT_OK(metadata, len)) {

            /* Check that run-time and compile-time structures match. */

            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                fprintf(stderr,
                        "Mismatch of fanotify metadata version.\n");
                exit(EXIT_FAILURE);
            }

            /* metadata->fd contains either FAN_NOFD, indicating a
               queue overflow, or a file descriptor (a nonnegative
               integer). Here, we simply ignore queue overflow. */

            if (metadata->fd >= 0) {

                /* Handle open permission event. */

                if (metadata->mask & FAN_OPEN_EXEC_PERM) {
                    printf("FAN_OPEN_EXEC_PERM: ");

                    /* Allow file to be opened. */

                    response.fd = metadata->fd;
                    response.response = FAN_ALLOW;
                    write(fd, &response, sizeof(response));
                }

                /* Retrieve and print pathname of the accessed file. */

                snprintf(procfd_path, sizeof(procfd_path),
                         "/proc/self/fd/%d", metadata->fd);
                path_len = readlink(procfd_path, path,
                                    sizeof(path) - 1);
                if (path_len == -1) {
                    perror("readlink");
                    exit(EXIT_FAILURE);
                }

                path[path_len] = '\0';
                printf("File %s\n", path);

                struct stat sb;

                if (fstat(metadata->fd, &sb) == -1) {
                    perror("fstat");
                    exit(EXIT_FAILURE);
                }

                printf("ID of containing device:  [%jx,%jx]\n",
                        (uintmax_t) major(sb.st_dev),
                        (uintmax_t) minor(sb.st_dev));

                printf("File type:                ");

                switch (sb.st_mode & S_IFMT) {
                case S_IFBLK:  printf("block device\n");            break;
                case S_IFCHR:  printf("character device\n");        break;
                case S_IFDIR:  printf("directory\n");               break;
                case S_IFIFO:  printf("FIFO/pipe\n");               break;
                case S_IFLNK:  printf("symlink\n");                 break;
                case S_IFREG:  printf("regular file\n");            break;
                case S_IFSOCK: printf("socket\n");                  break;
                default:       printf("unknown?\n");                break;
                }

                printf("I-node number:            %ju\n", (uintmax_t) sb.st_ino);

                printf("Mode:                     %jo (octal)\n",
                        (uintmax_t) sb.st_mode);

                printf("Link count:               %ju\n", (uintmax_t) sb.st_nlink);
                printf("Ownership:                UID=%ju   GID=%ju\n",
                        (uintmax_t) sb.st_uid, (uintmax_t) sb.st_gid);

                printf("Preferred I/O block size: %jd bytes\n",
                        (intmax_t) sb.st_blksize);
                printf("File size:                %jd bytes\n",
                        (intmax_t) sb.st_size);
                printf("Blocks allocated:         %jd\n",
                        (intmax_t) sb.st_blocks);

                printf("Last status change:       %s", ctime(&sb.st_ctime));
                printf("Last file access:         %s", ctime(&sb.st_atime));
                printf("Last file modification:   %s", ctime(&sb.st_mtime));

                /* Close the file descriptor of the event. */

                close(metadata->fd);
            }

            /* Advance to next event. */

            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}

int
main(int argc, char *argv[])
{
    char buf;
    int fd, poll_num, mountns_fd, pidns_fd;
    nfds_t nfds;
    struct pollfd fds[2];

    if (argc != 4) {
        fprintf(stderr, "Usage: %s MOUNTNS_FILE PIDNS_FILE MOUNT\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("Press enter key to terminate.\n");

    mountns_fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    pidns_fd = open(argv[2], O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    /* Enter mount namespace */
    if (setns(mountns_fd, CLONE_NEWNS)) {
        perror("setns");
        exit(EXIT_FAILURE);
    }

    /* Enter PID namespace */
    if (setns(pidns_fd, CLONE_NEWPID)) {
        perror("setns");
        exit(EXIT_FAILURE);
    }

    /* Mount procfs in the new PID namespace */
    if (mount("/proc", "/proc", "proc", MS_NOSUID|MS_NODEV, NULL)) {
        perror("mount");
        exit(EXIT_FAILURE);
    }

    /* Create the file descriptor for accessing the fanotify API. */

    fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS,
                       O_RDONLY | O_LARGEFILE);
    if (fd == -1) {
        perror("fanotify_init");
        exit(EXIT_FAILURE);
    }

    /* Mark the mount for:
       - permission events before opening files
       - notification events after closing a write-enabled
         file descriptor. */

    if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                      FAN_OPEN_EXEC_PERM, AT_FDCWD,
                      argv[3]) == -1) {
        perror("fanotify_mark");
        exit(EXIT_FAILURE);
    }

    /* Prepare for polling. */

    nfds = 2;

    fds[0].fd = STDIN_FILENO;       /* Console input */
    fds[0].events = POLLIN;

    fds[1].fd = fd;                 /* Fanotify input */
    fds[1].events = POLLIN;

    /* This is the loop to wait for incoming events. */

    printf("Listening for events.\n");

    while (1) {
        poll_num = poll(fds, nfds, -1);
        if (poll_num == -1) {
            if (errno == EINTR)     /* Interrupted by a signal */
                continue;           /* Restart poll() */

            perror("poll");         /* Unexpected error */
            exit(EXIT_FAILURE);
        }

        if (poll_num > 0) {
            if (fds[0].revents & POLLIN) {

                /* Console input is available: empty stdin and quit. */

                while (read(STDIN_FILENO, &buf, 1) > 0 && buf != '\n')
                    continue;
                break;
            }

            if (fds[1].revents & POLLIN) {

                /* Fanotify events are available. */

                handle_events(fd);
            }
        }
    }

    printf("Listening for events stopped.\n");
    exit(EXIT_SUCCESS);
}
