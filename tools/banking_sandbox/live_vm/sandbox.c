/* Fail-closed, ordinary-user launcher for one fixed diskless TCG VM profile.
 * Landlock ABI >=2: read/execute only the sealed bundle; no host filesystem writes.
 * seccomp: no network, mount/namespace changes, ptrace, kernel modules, or subprocesses.
 * Anonymous emulator threads remain permitted. No host devices/directory passthrough.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(n),0,1), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
static int rule(int ruleset, const char *path, uint64_t access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) return -1;
    struct landlock_path_beneath_attr attr = {.allowed_access=access, .parent_fd=fd};
    int result = syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
    close(fd); return result;
}
static int restrict_fs(const char *bundle) {
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 2) return -1;
    struct landlock_ruleset_attr attr = {.handled_access_fs=(1ULL<<14)-1}; /* ABI 1+2 rights through REFER */
    int ruleset = syscall(SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
    if (ruleset < 0) return -1;
    if (rule(ruleset, bundle, LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_READ_DIR|LANDLOCK_ACCESS_FS_EXECUTE)
        || rule(ruleset, "/dev/urandom", LANDLOCK_ACCESS_FS_READ_FILE)
        || rule(ruleset, "/dev/null", LANDLOCK_ACCESS_FS_READ_FILE)
        || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        || syscall(SYS_landlock_restrict_self, ruleset, 0)) { close(ruleset); return -1; }
    close(ruleset); return 0;
}
static int restrict_syscalls(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, 0x40000000, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
        DENY(SYS_socket), DENY(SYS_socketpair), DENY(SYS_connect), DENY(SYS_bind),
        DENY(SYS_listen), DENY(SYS_accept), DENY(SYS_accept4),
        DENY(SYS_mount), DENY(SYS_umount2), DENY(SYS_pivot_root), DENY(SYS_chroot),
        DENY(SYS_truncate), DENY(SYS_chmod), DENY(SYS_fchmod), DENY(SYS_fchmodat), DENY(452), /* fchmodat2 */
        DENY(SYS_chown), DENY(SYS_lchown), DENY(SYS_fchown), DENY(SYS_fchownat),
        DENY(SYS_utime), DENY(SYS_utimes), DENY(SYS_futimesat), DENY(SYS_utimensat),
        DENY(SYS_setxattr), DENY(SYS_lsetxattr), DENY(SYS_fsetxattr),
        DENY(SYS_removexattr), DENY(SYS_lremovexattr), DENY(SYS_fremovexattr),
        DENY(SYS_link), DENY(SYS_linkat), DENY(SYS_unlink), DENY(SYS_unlinkat),
        DENY(SYS_rename), DENY(SYS_renameat), DENY(SYS_renameat2),
        DENY(SYS_mkdir), DENY(SYS_mkdirat), DENY(SYS_rmdir),
        DENY(SYS_mknod), DENY(SYS_mknodat), DENY(SYS_symlink), DENY(SYS_symlinkat),
        DENY(SYS_shmget), DENY(SYS_shmat), DENY(SYS_shmctl),
        DENY(SYS_msgget), DENY(SYS_msgsnd), DENY(SYS_msgrcv), DENY(SYS_msgctl),
        DENY(SYS_semget), DENY(SYS_semop), DENY(SYS_semctl), DENY(SYS_semtimedop),
        DENY(SYS_pidfd_open), DENY(SYS_pidfd_getfd), DENY(SYS_pidfd_send_signal),
        DENY(SYS_kill), DENY(SYS_tkill),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_tgkill, 0, 4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, (uint32_t)getpid(), 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        DENY(SYS_unshare), DENY(SYS_setns), DENY(SYS_ptrace),
        DENY(SYS_process_vm_readv), DENY(SYS_process_vm_writev),
        DENY(SYS_init_module), DENY(SYS_finit_module), DENY(SYS_delete_module),
        DENY(SYS_bpf), DENY(SYS_perf_event_open), DENY(SYS_io_uring_setup),
        DENY(SYS_open_by_handle_at), DENY(SYS_name_to_handle_at), DENY(SYS_execveat),
        DENY(SYS_fork), DENY(SYS_vfork),
        /* Force libc's ordinary clone fallback, whose flags we can inspect. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_clone3, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|ENOSYS),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_clone, 0, 4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, CLONE_THREAD, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        /* Landlock ABI2 lacks TRUNCATE: explicitly deny all writable path opens. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_open, 0, 4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_openat, 0, 4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[2])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_openat2, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|ENOSYS),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program = {.len=sizeof filter/sizeof filter[0], .filter=filter};
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}
int main(int argc, char **argv) {
    if (getuid()==0 || geteuid()==0 || argc!=3 || argv[1][0]!='/' || strlen(argv[1])>3000 || strlen(argv[2])!=64)
        return 64;
    for (int i=0;i<64;i++) if (!((argv[2][i]>='0'&&argv[2][i]<='9')||(argv[2][i]>='a'&&argv[2][i]<='f'))) return 64;
    struct __user_cap_header_struct cap_header = {.version=_LINUX_CAPABILITY_VERSION_3, .pid=0};
    struct __user_cap_data_struct caps[2];
    if (syscall(SYS_capget, &cap_header, caps) || caps[0].effective || caps[0].permitted || caps[0].inheritable
        || caps[1].effective || caps[1].permitted || caps[1].inheritable) return 64;
    char loader[4096], libs[4096], qemu[4096], bios[4096], kernel[4096], initrd[4096], cmdline[256];
    snprintf(loader,sizeof loader,"%s/emulator/libc.so",argv[1]);
    snprintf(libs,sizeof libs,"%s/emulator/lib",argv[1]);
    snprintf(qemu,sizeof qemu,"%s/emulator/qemu",argv[1]);
    snprintf(bios,sizeof bios,"%s/emulator/share/qemu",argv[1]);
    snprintf(kernel,sizeof kernel,"%s/kernel",argv[1]);
    snprintf(initrd,sizeof initrd,"%s/initramfs.cpio.gz",argv[1]);
    snprintf(cmdline,sizeof cmdline,"console=ttyS0 quiet panic=-1 oops=panic rdinit=/init cryptoscan_tbf_nonce=%s",argv[2]);
    struct rlimit core={0,0}, cpu={120,120}, files={128,128}, memory={3ULL*1024*1024*1024,3ULL*1024*1024*1024};
    if (setrlimit(RLIMIT_CORE,&core) || setrlimit(RLIMIT_CPU,&cpu) || setrlimit(RLIMIT_NOFILE,&files)
        || setrlimit(RLIMIT_AS,&memory) || restrict_fs(argv[1]) || restrict_syscalls()) {
        fputs("DISPOSABLE_TBF_SANDBOX_UNAVAILABLE\n",stderr); return 77;
    }
    fputs("CRYPTOSCAN_TBF_SANDBOX=LANDLOCK_SECCOMP_ACTIVE\n",stdout); fflush(stdout);
    char *args[]={loader,"--library-path",libs,qemu,"-L",bios,"-no-user-config","-nodefaults",
        "-machine","pc","-accel","tcg,thread=single","-cpu","qemu64","-m","256M","-smp","1",
        "-nic","none","-display","none","-monitor","none","-serial","stdio","-no-reboot",
        "-kernel",kernel,"-initrd",initrd,"-append",cmdline,NULL};
    char *env[]={"PATH=/usr/bin:/bin","LC_ALL=C",NULL};
    execve(loader,args,env);
    fputs("DISPOSABLE_TBF_LAUNCH_FAILED\n",stderr); return 77;
}
