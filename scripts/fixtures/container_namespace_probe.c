/* Owned rootless Linux namespace fixture. No customer code or credentials. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
static void refuse(void){_exit(70);}
int main(int argc,char **argv){
 if(argc<2 || getpid()!=1)refuse();
 struct rlimit memory={128*1024*1024,128*1024*1024},files={32,32},output={65536,65536},cpu={2,2};
 if(setrlimit(RLIMIT_AS,&memory)||setrlimit(RLIMIT_NOFILE,&files)||setrlimit(RLIMIT_FSIZE,&output)||setrlimit(RLIMIT_CPU,&cpu))refuse();
 struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
 struct __user_cap_data_struct caps[2]={{0},{0}};
 if(syscall(SYS_capset,&h,caps)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))refuse();
 struct sock_filter filter[]={
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
 BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,0x40000000,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
 DENY(SYS_socket),DENY(SYS_mount),DENY(SYS_umount2),DENY(SYS_ptrace),DENY(SYS_setns),DENY(SYS_unshare),
 DENY(SYS_clone3),DENY(SYS_clone),DENY(SYS_chroot),DENY(SYS_pivot_root),DENY(SYS_fork),DENY(SYS_vfork),DENY(SYS_execve),DENY(SYS_execveat),
 BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
 struct sock_fprog policy={sizeof(filter)/sizeof(filter[0]),filter};
 if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&policy))refuse();
 struct stat namespaces[6],exe;
 const char *names[] = {"user","mnt","pid","net","ipc","uts"};
 for(int i=0;i<6;i++){char p[80];snprintf(p,sizeof(p),"/proc/self/ns/%s",names[i]);if(stat(p,&namespaces[i]))refuse();}
 if(stat("/proc/self/exe",&exe))refuse();
 char db[512];int fd=open("/var/lib/dpkg/status",O_RDONLY);if(fd<0)refuse();
 ssize_t n=read(fd,db,sizeof(db));close(fd);if(n<=0 || (size_t)n>=sizeof(db))refuse();
 int outside=open(argv[1],O_RDONLY);int outside_denied=(outside<0&&errno==ENOENT);if(outside>=0)close(outside);
 int writefd=open("/write-probe",O_CREAT|O_WRONLY,0600);int readonly=(writefd<0&&errno==EROFS);if(writefd>=0)close(writefd);
 errno=0;int sock=syscall(SYS_socket,2,1,0);int socket_denied=(sock<0&&errno==EPERM);
 errno=0;int mount_result=syscall(SYS_mount,"none","/proc","tmpfs",0,NULL);int mount_denied=(mount_result<0&&errno==EPERM);
 void *large=malloc(256*1024*1024);int memory_limited=(large==NULL);free(large);
 int fds[64],count=0;while(count<64){int v=open("/var/lib/dpkg/status",O_RDONLY);if(v<0)break;fds[count++]=v;}
 int fd_limited=(errno==EMFILE);for(int i=0;i<count;i++)close(fds[i]);
 if(syscall(SYS_capget,&h,caps))refuse();
 printf("{\"pid\":%d,\"namespaces\":{",getpid());
 for(int i=0;i<6;i++)printf("%s\"%s\":%llu",i?",":"",names[i],(unsigned long long)namespaces[i].st_ino);
 printf("},\"executable_inode\":%llu,\"database_hex\":\"",(unsigned long long)exe.st_ino);
 for(int i=0;i<n;i++)printf("%02x",(unsigned char)db[i]);
 printf("\",\"outside_denied\":%s,\"readonly_root\":%s,\"socket_denied\":%s,\"mount_denied\":%s,\"memory_limit_exercised\":%s,\"fd_limit_exercised\":%s,\"effective_caps_zero\":%s,\"no_new_privileges\":%s}",
 outside_denied?"true":"false",readonly?"true":"false",socket_denied?"true":"false",mount_denied?"true":"false",
 memory_limited?"true":"false",fd_limited?"true":"false",(caps[0].effective==0&&caps[1].effective==0)?"true":"false",
 prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1?"true":"false");
 fflush(stdout);
 if(argc>2 && argv[2][0]=='h')for(;;)pause();
 return 0;
}
