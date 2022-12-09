#include <sys/fanotify.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "print_lib.h"

#include "easy_security.hpp"
#include "patterns.hpp"
#include "sqlite3/sqlite3.h"

static bool IsPermEvent(int event) noexcept
{
    return event & (FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_ACCESS_PERM);
}

int easy_security_start()
{
    int scan_fd = fanotify_init(FAN_CLASS_PRE_CONTENT, O_RDONLY);
    CHECK_NNEG(scan_fd);

    const uint64_t mask = 0
                          | FAN_ACCESS
                          | FAN_MODIFY
                          | FAN_CLOSE
                          | FAN_OPEN
                          | FAN_OPEN_PERM
                          | FAN_ACCESS_PERM
                          ;
    if (int res = fanotify_mark(scan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD, "/"); res < 0)
    {
        close(scan_fd);
        PRINT_ERR(fanotify_mark(scan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD, "/"));
        return -errno;
    }

    const char data_base_backup_files[] = "backup_files.db";
    CHECK_NNEG(fanotify_mark(scan_fd, FAN_MARK_ADD, FAN_EVENT_ON_CHILD | mask, AT_FDCWD, "."));

    CHECK_NNEG(fanotify_mark(scan_fd, FAN_MARK_ADD | FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY,
                             mask, AT_FDCWD, "."));
    try
    {
        // Just now exist only one pattern
        es::EasySecurity detector{
            { patterns::encrypt_file_use_fseek() },
            data_base_backup_files
        };

        printf("Start scanning\n");

        int invalid_version_counter = 0;
        const int invalid_version_counter_max = 10;

        int queue_overflow_counter = 0;
        const int queue_overflow_counter_max = 10;

        fanotify_event_metadata md_buf[4096 / sizeof(fanotify_event_metadata)] = {};
        while(true)
        {
            int md_buf_len = read(scan_fd, md_buf, sizeof(md_buf));
            if (md_buf_len < 0 || md_buf_len == EOF)
            {
                PRINT_ERR(read);
                return -errno;
            }

            for (fanotify_event_metadata* md = md_buf;
                FAN_EVENT_OK(md, md_buf_len);
                md = FAN_EVENT_NEXT(md, md_buf_len))
            {
                if (md->vers != FANOTIFY_METADATA_VERSION)
                {
                    if (++invalid_version_counter == invalid_version_counter_max)
                        return -1;

                    fprintf(stderr, "Invalid version!\n");
                    continue;
                }

                if (md->fd == FAN_NOFD)
                {
                    if (++queue_overflow_counter == queue_overflow_counter_max)
                        return -1;

                    fprintf(stderr, "Queue overflowed!\n");
                    continue;
                }

                if (md->fd < 0)
                    continue;

                const bool is_need_close = detector.Step(md->pid, md->fd, md->mask, scan_fd, mask);
                if (is_need_close)
                {
                    if (IsPermEvent(md->mask))
                    {
                        struct fanotify_response resp = {
                            .fd = md->fd,
                            .response = FAN_ALLOW
                        };
                        CHECK_TRUE(write(scan_fd, &resp, sizeof(resp)) == sizeof(resp));
                    }
                    close(md->fd);
                }
            }
        }

        printf("finished\n");
        if (errno)
            perror("Error detected");

    } catch(es::SqliteException& exc)
    {
        fprintf(stderr, "errmsg: %s\n", exc.what());
        fprintf(stderr, "errcode: %d\n", exc.err_code());
    } catch(std::exception& exc)
    {
        fprintf(stderr, "errmsg: %s\n", exc.what());
    }
    close(scan_fd);

    return 0;
}

int main()
{
    return easy_security_start();
}
