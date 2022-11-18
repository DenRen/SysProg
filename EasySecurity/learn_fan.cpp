#include <fcntl.h>
#include <sys/fanotify.h>
#include <cstdio>
#include <cstdlib>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

#include "print_lib.h"

/*
Rec:
    ignore: tmp, own files
    fast read: buf, disable thread safe
*/

void print_mask(uint64_t mask)
{
    int ctr = 0;
    #define DETAIL_PRINT_MASK(bit_mask)\
    do {\
        if (mask & bit_mask)\
        {\
            if(++ctr > 1)\
                printf(" ");\
            const char* event = #bit_mask;\
            printf("%s", event + sizeof("FAN_") - 1);\
        }\
    } while(0)

    DETAIL_PRINT_MASK(FAN_ACCESS);
    DETAIL_PRINT_MASK(FAN_OPEN);
    DETAIL_PRINT_MASK(FAN_OPEN_EXEC);
    DETAIL_PRINT_MASK(FAN_ATTRIB);
    DETAIL_PRINT_MASK(FAN_CREATE);
    DETAIL_PRINT_MASK(FAN_DELETE);
    DETAIL_PRINT_MASK(FAN_DELETE_SELF);
    DETAIL_PRINT_MASK(FAN_MOVED_FROM);
    DETAIL_PRINT_MASK(FAN_MOVED_TO);
    DETAIL_PRINT_MASK(FAN_MOVE_SELF);
    DETAIL_PRINT_MASK(FAN_MODIFY);
    DETAIL_PRINT_MASK(FAN_CLOSE_WRITE);
    DETAIL_PRINT_MASK(FAN_CLOSE_NOWRITE);
    DETAIL_PRINT_MASK(FAN_Q_OVERFLOW);
    DETAIL_PRINT_MASK(FAN_ACCESS_PERM);
    DETAIL_PRINT_MASK(FAN_OPEN_PERM);
    DETAIL_PRINT_MASK(FAN_OPEN_EXEC_PERM);

    #undef DETAIL_PRINT_MASK
}

int print_cmdline(const char* path)
{
    int fd = open(path, O_RDONLY);
    CHECK_NNEG(fd);

    char buf[512];
    int size = read(fd, buf, sizeof(buf));
    close(fd);
    if (size < 0)
    {
        PRINT_ERR("read");
        return -errno;
    }
    buf[size - 1] = '\0';

    CHECK_TRUE(write(STDOUT_FILENO, buf, size) == size);

    return 0;
}

int print_md(const struct fanotify_event_metadata* md)
{
    printf("{event len: %u, vers: %u, md_ln: %u, mask: %6llx, fd: %d, pid: %d -> [",
        md->event_len, md->vers, md->metadata_len, md->mask, md->fd, md->pid
    );
    print_mask(md->mask);
    printf("]} ");

    char path[PATH_MAX];


    // Print cmdline
    fflush(stdout);
    snprintf(path, sizeof(path), "/proc/%d/comm", md->pid);
    CHECK_NNEG(print_cmdline(path));

    // Print file name
    snprintf(path, sizeof(path), "/proc/self/fd/%d", md->fd);

    int nbytes = readlink(path, path, sizeof(path));
    CHECK_NNEG(nbytes);
    path[nbytes] = '\0';

    printf(": \"%s\"", path);

    return 0;
}

int main ()
{
    int scan_fd = fanotify_init(FAN_CLASS_CONTENT, O_RDONLY);
    CHECK_NNEG(scan_fd);

    const uint64_t mask = 0
                          | FAN_ACCESS
                          | FAN_MODIFY
                          | FAN_CLOSE
                          | FAN_OPEN
                        //   | FAN_OPEN_EXEC
                        //   | FAN_ONDIR
                        //   | FAN_EVENT_ON_CHILD
                          | FAN_OPEN_PERM
                          | FAN_ACCESS_PERM
                          ;
    CHECK_NNEG(fanotify_mark(scan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD, "/"));
    CHECK_NNEG(fanotify_mark(scan_fd, FAN_MARK_ADD | FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY,
                             mask, AT_FDCWD, ".log"));

    printf("Start scanning\n");
    struct fanotify_event_metadata md = {};
    while(read(scan_fd, &md, sizeof(md)) != EOF)
    {
        CHECK_NNEG(print_md(&md));

        if (md.vers != FANOTIFY_METADATA_VERSION)
            printf(" -> invalid version");
            
        printf("\n");

        if (md.mask & (FAN_ALL_PERM_EVENTS | FAN_OPEN_EXEC_PERM))
        {
            // char symb = 0;
            // printf("Access? [y/n] ");
            // fflush(stdout);
            // while(scanf("%c", &symb) != 1);

            struct fanotify_response resp = {
                .fd = md.fd,
                .response = FAN_ALLOW
            };
            CHECK_TRUE(write(scan_fd, &resp, sizeof(resp)) == sizeof(resp));
        }
        close(md.fd);
    }

    printf("finished\n");
    if (errno)
        perror("detected error");

    close(scan_fd);
}