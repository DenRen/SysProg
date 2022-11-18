#include <sys/fanotify.h>
#include <fcntl.h>

#include "print_lib.h"

#include "easy_security.hpp"
#include "patterns.hpp"

/*
    * Detect and notify
    * Detect, stop and asc
    * Add colors to output
    * Add logging
*/

static bool IsPermEvent(int event) noexcept
{
    return event & (FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_ACCESS_PERM);
}

int main()
{
    int scan_fd = fanotify_init(FAN_CLASS_CONTENT, O_RDONLY);
    CHECK_NNEG(scan_fd);

    const uint64_t mask = 0
                          | FAN_ACCESS
                          | FAN_MODIFY
                          | FAN_CLOSE
                          | FAN_OPEN
                          | FAN_OPEN_PERM
                          | FAN_ACCESS_PERM
                          ;
    CHECK_NNEG(fanotify_mark(scan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD, "/"));
    // CHECK_NNEG(fanotify_mark(scan_fd, FAN_MARK_ADD | FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY,
    //                          mask, AT_FDCWD, ".log"));

    es::EasySecurity detector({encryptor_patterns::enc_pattern()});

    printf("Start scanning\n");
    struct fanotify_event_metadata md = {};
    while(read(scan_fd, &md, sizeof(md)) != EOF)
    {
        if (md.vers != FANOTIFY_METADATA_VERSION)
        {
            fprintf(stderr, "invalid version\n");
            continue;
        }

        detector.Step(md.pid, md.fd, md.mask);

        if (IsPermEvent(md.mask))
        {
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
