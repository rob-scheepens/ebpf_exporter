#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define BPF_PROG_PATH "/sys/fs/bpf/prog.o"

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, task_fd;
    char buf[256];

    /* Load BPF program */
    obj = bpf_object__open_file(BPF_PROG_PATH, NULL);
    if (!obj) {
        printf("Failed to load BPF program\n");
        return 1;
    }

    /* Load program */
    if (bpf_object__load(obj) != 0) {
        printf("Failed to load BPF program: %s\n", bpf_object__error(obj));
        return 1;
    }

    /* Get program file descriptor */
    prog = bpf_object__find_program_by_name(obj, "get_task_name");
    if (!prog) {
        printf("Failed to find BPF program\n");
        return 1;
    }

    /* Attach program to current task */
    prog_fd = bpf_program__fd(prog);
    task_fd = bpf_get_current_task();
    if (task_fd < 0) {
        printf("Failed to get current task\n");
        return 1;
    }

    if (bpf_prog_attach(prog_fd, task_fd, BPF_SK_SKB_STREAM_PARSER, 0) < 0) {
        printf("Failed to attach BPF program: %s\n", strerror(errno));
        return 1;
    }

    /* Read output buffer */
    if (bpf_prog_read(prog_fd, buf, sizeof(buf)) < 0) {
        printf("Failed to read output buffer: %s\n", strerror(errno));
        return 1;
    }

    printf("Current process name: %s\n", buf);

    return 0;
}

