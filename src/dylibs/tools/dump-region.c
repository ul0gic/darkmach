/* Read a memory region from a running process (task_for_pid / task_read_for_pid /
 * task_name_for_pid). Usage: ./dump-region <pid> <hex_address> <size> <output_file> */
#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

/* task_read_for_pid is available but not always declared in headers */
extern kern_return_t task_read_for_pid(mach_port_t target_tport, int pid, mach_port_t *t);

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <pid> <hex_address> <size> <output_file>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    mach_vm_address_t address = strtoull(argv[2], NULL, 16);
    mach_vm_size_t size = strtoull(argv[3], NULL, 0);
    const char *outfile = argv[4];

    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr;

    /* Try 1: task_for_pid (full access — usually blocked by SIP) */
    kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr == KERN_SUCCESS) {
        fprintf(stderr, "[1] task_for_pid: SUCCESS (full access)\n");
    } else {
        fprintf(stderr, "[1] task_for_pid: %s\n", mach_error_string(kr));

        /* Try 2: task_read_for_pid (read-only port — newer API) */
        kr = task_read_for_pid(mach_task_self(), pid, &task);
        if (kr == KERN_SUCCESS) {
            fprintf(stderr, "[2] task_read_for_pid: SUCCESS (read access)\n");
        } else {
            fprintf(stderr, "[2] task_read_for_pid: %s\n", mach_error_string(kr));

            /* Try 3: task_name_for_pid (name port only) */
            kr = task_name_for_pid(mach_task_self(), pid, &task);
            if (kr == KERN_SUCCESS) {
                fprintf(stderr, "[3] task_name_for_pid: SUCCESS (name only)\n");
            } else {
                fprintf(stderr, "[3] task_name_for_pid: %s\n", mach_error_string(kr));
                return 1;
            }
        }
    }

    /* Try to read memory */
    vm_offset_t data;
    mach_msg_type_number_t data_count;

    fprintf(stderr, "Reading 0x%llx bytes at 0x%llx from PID %d...\n", size, address, pid);

    kr = mach_vm_read(task, address, size, &data, &data_count);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "mach_vm_read: %s\n", mach_error_string(kr));

        /* Try vm_read as fallback */
        kr = vm_read(task, (vm_address_t)address, (vm_size_t)size, &data, &data_count);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "vm_read: %s\n", mach_error_string(kr));
            return 1;
        }
    }

    fprintf(stderr, "Read %u bytes successfully\n", data_count);

    /* Write to file */
    FILE *f = fopen(outfile, "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite((void *)data, 1, data_count, f);
    fclose(f);
    fprintf(stderr, "Written to %s\n", outfile);

    mach_vm_deallocate(mach_task_self(), data, data_count);
    return 0;
}
