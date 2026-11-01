#include "bp.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#ifdef _WIN32
#include <iphlpapi.h>
#include <sddl.h>
#include <io.h>
#include <fcntl.h>
#include <direct.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <time.h>
#endif

int bp_platform_init(void) {
#ifdef _WIN32
    WSADATA data;
    return WSAStartup(MAKEWORD(2,2), &data) == 0;
#else
    return 1;
#endif
}
void bp_platform_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}
uint64_t bp_now(void) {
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}
void bp_sleep(unsigned ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000};
    while (nanosleep(&ts, &ts) && errno == EINTR) {}
#endif
}
void bp_mutex_init(bp_mutex *m) {
#ifdef _WIN32
    InitializeCriticalSection(m);
#else
    pthread_mutex_init(m, NULL);
#endif
}
void bp_lock(bp_mutex *m) {
#ifdef _WIN32
    EnterCriticalSection(m);
#else
    pthread_mutex_lock(m);
#endif
}
void bp_unlock(bp_mutex *m) {
#ifdef _WIN32
    LeaveCriticalSection(m);
#else
    pthread_mutex_unlock(m);
#endif
}
void bp_socket_close(bp_socket s) {
    if (s == BP_BAD_SOCKET) return;
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}
static int nonblocking(bp_socket s) {
#ifdef _WIN32
    u_long one = 1; return ioctlsocket(s, FIONBIO, &one) == 0;
#else
    return fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK) == 0;
#endif
}
int bp_interface(const char *input, char output[256]) {
    struct in_addr ip;
    if (inet_pton(AF_INET, input, &ip) == 1) { snprintf(output,256,"%s",input); return 1; }
#ifdef _WIN32
    ULONG size = 16384; IP_ADAPTER_ADDRESSES *list = malloc(size), *a;
    if (!list) return 0;
    if (GetAdaptersAddresses(AF_INET,0,NULL,list,&size) == ERROR_BUFFER_OVERFLOW) {
        free(list); list = malloc(size); if (!list) return 0;
    }
    if (GetAdaptersAddresses(AF_INET,0,NULL,list,&size) != NO_ERROR) { free(list); return 0; }
    for (a = list; a; a = a->Next) {
        char name[256];
        WideCharToMultiByte(CP_UTF8,0,a->FriendlyName,-1,name,sizeof(name),NULL,NULL);
        if (strcmp(input,name) && strcmp(input,a->AdapterName)) continue;
        for (IP_ADAPTER_UNICAST_ADDRESS *u=a->FirstUnicastAddress;u;u=u->Next) {
            if (u->Address.lpSockaddr->sa_family != AF_INET) continue;
            inet_ntop(AF_INET,&((struct sockaddr_in*)u->Address.lpSockaddr)->sin_addr,output,256);
            free(list); return 1;
        }
    }
    free(list);
#else
    struct ifaddrs *list, *a;
    if (getifaddrs(&list)) return 0;
    for (a=list;a;a=a->ifa_next) {
        if (!a->ifa_addr || a->ifa_addr->sa_family != AF_INET || strcmp(a->ifa_name,input)) continue;
        inet_ntop(AF_INET,&((struct sockaddr_in*)a->ifa_addr)->sin_addr,output,256);
        freeifaddrs(list); return 1;
    }
    freeifaddrs(list);
#endif
    return 0;
}
bp_socket bp_listen(const char *address, uint16_t port) {
    struct sockaddr_in addr; bp_socket s=socket(AF_INET,SOCK_STREAM,0);
    if (s == BP_BAD_SOCKET) return s;
#ifndef _WIN32
    int reuse=1;setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
#endif
    memset(&addr,0,sizeof(addr)); addr.sin_family=AF_INET; addr.sin_port=htons(port);
    if (inet_pton(AF_INET,address,&addr.sin_addr)!=1 || bind(s,(struct sockaddr*)&addr,sizeof(addr)) || listen(s,16)) {
        bp_socket_close(s); return BP_BAD_SOCKET;
    }
    return s;
}
static int wait_socket(bp_socket s, int writing, uint64_t deadline) {
    fd_set fds; struct timeval tv; uint64_t now=bp_now();
    if (now >= deadline) return 0;
    tv.tv_sec=(long)((deadline-now)/1000); tv.tv_usec=(long)(((deadline-now)%1000)*1000);
    FD_ZERO(&fds); FD_SET(s,&fds);
    return select((int)s+1,writing?NULL:&fds,writing?&fds:NULL,NULL,&tv)>0;
}
bp_socket bp_connect(const char *address, uint16_t port) {
    struct addrinfo hints, *list=NULL, *a; char service[8]; bp_socket s=BP_BAD_SOCKET;
    memset(&hints,0,sizeof(hints)); hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
    snprintf(service,sizeof(service),"%u",port);
    if (getaddrinfo(address,service,&hints,&list)) return s;
    for (a=list;a;a=a->ai_next) {
        s=socket(a->ai_family,a->ai_socktype,a->ai_protocol);
        if (s==BP_BAD_SOCKET) continue;
        if (!nonblocking(s)) { bp_socket_close(s); s=BP_BAD_SOCKET; continue; }
        int result=connect(s,a->ai_addr,(int)a->ai_addrlen);
        if (result==0 || wait_socket(s,1,bp_now()+BP_TIMEOUT)) {
            int error=0;
#ifdef _WIN32
            int len=sizeof(error);
#else
            socklen_t len=sizeof(error);
#endif
            if (!getsockopt(s,SOL_SOCKET,SO_ERROR,(char*)&error,&len) && !error) break;
        }
        bp_socket_close(s); s=BP_BAD_SOCKET;
    }
    freeaddrinfo(list); return s;
}
int bp_tls_run(SSL *ssl, bp_socket sock, int shutdown) {
    uint64_t deadline=bp_now()+BP_TIMEOUT;
    if (!nonblocking(sock)) return 0;
    for (;;) {
        if (bp_now()>=deadline) return 0;
        ERR_clear_error();
        int result=shutdown?SSL_shutdown(ssl):SSL_do_handshake(ssl);
        if (result==1) return 1;
        if (shutdown && result==0) continue;
        int error=SSL_get_error(ssl,result);
        if (error!=SSL_ERROR_WANT_READ && error!=SSL_ERROR_WANT_WRITE) return 0;
        if (!wait_socket(sock,error==SSL_ERROR_WANT_WRITE,deadline)) return 0;
    }
}
FILE *bp_private_create(const char *path) {
#ifdef _WIN32
    PSECURITY_DESCRIPTOR sd=NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA("D:P(A;;FA;;;OW)(A;;FA;;;SY)",SDDL_REVISION_1,&sd,NULL)) return NULL;
    SECURITY_ATTRIBUTES sa={sizeof(sa),sd,FALSE};
    HANDLE h=CreateFileA(path,GENERIC_WRITE,0,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    LocalFree(sd); if (h==INVALID_HANDLE_VALUE) return NULL;
    int fd=_open_osfhandle((intptr_t)h,_O_BINARY|_O_WRONLY);
    if (fd<0) { CloseHandle(h); return NULL; }
    return _fdopen(fd,"wb");
#else
    int fd=open(path,O_CREAT|O_EXCL|O_WRONLY,0600);
    return fd<0?NULL:fdopen(fd,"wb");
#endif
}
int bp_self_path(char *out, size_t cap) {
#ifdef _WIN32
    DWORD n=GetModuleFileNameA(NULL,out,(DWORD)cap); return n>0 && n<cap;
#else
    ssize_t n=readlink("/proc/self/exe",out,cap-1); if(n<0) return 0; out[n]=0; return 1;
#endif
}
int bp_cwd(char *out,size_t cap) {
#ifdef _WIN32
    return _getcwd(out,(int)cap)!=NULL;
#else
    return getcwd(out,cap)!=NULL;
#endif
}
int bp_chdir(const char *path) {
#ifdef _WIN32
    return _chdir(path)==0;
#else
    return chdir(path)==0;
#endif
}
void bp_print_bytes(const unsigned char *s, size_t n) {
    for(size_t i=0;i<n;i++) {
        unsigned c=s[i];
        if(c=='\n'||c=='\t'||(c>=32&&c<127)) putchar((int)c);
        else if(c!='\r') printf("\\x%02x",c);
    }
    fflush(stdout);
}
