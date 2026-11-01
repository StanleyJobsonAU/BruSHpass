#include "bp.h"
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <direct.h>
#define getcwd _getcwd
#define chdir _chdir
#else
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#endif

int bp_execute(const char *command,unsigned char *output,size_t cap,size_t *length) {
    *length=0;
    if(!strncmp(command,"cd",2)&&(command[2]==0||command[2]==' '||command[2]=='\t')) {
        const char *arg=command+2;while(*arg==' '||*arg=='\t')arg++;
        char path[1024],cwd[2048];size_t n=strlen(arg);
        if(n>=sizeof(path))return 2;memcpy(path,arg,n+1);
        if(n>=2&&((path[0]=='"'&&path[n-1]=='"')||(path[0]=='\''&&path[n-1]=='\''))) { path[n-1]=0;memmove(path,path+1,n-1); }
        if(path[0]&&chdir(path)) { const char *message="cd: could not change directory\n";*length=strlen(message);memcpy(output,message,*length);return 1; }
        if(!getcwd(cwd,sizeof(cwd)))return 1;
        n=strlen(cwd);if(n+1>cap)return 1;memcpy(output,cwd,n);output[n]='\n';*length=n+1;return 0;
    }
    uint64_t deadline=bp_now()+15000;int status=0,truncated=0;
#ifdef _WIN32
    SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};HANDLE read_pipe=NULL,write_pipe=NULL,input=NULL,job=NULL;
    STARTUPINFOA si;PROCESS_INFORMATION pi;memset(&si,0,sizeof(si));memset(&pi,0,sizeof(pi));si.cb=sizeof(si);
    if(!CreatePipe(&read_pipe,&write_pipe,&sa,0)||!SetHandleInformation(read_pipe,HANDLE_FLAG_INHERIT,0))goto fail;
    input=CreateFileA("NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(input==INVALID_HANDLE_VALUE){input=NULL;goto fail;}
    si.dwFlags=STARTF_USESTDHANDLES;si.hStdInput=input;si.hStdOutput=write_pipe;si.hStdError=write_pipe;
    char shell[MAX_PATH],line[1024];UINT n=GetSystemDirectoryA(shell,sizeof(shell));
    if(!n||n+9>=sizeof(shell))goto fail;strcat(shell,"\\cmd.exe");
    if(snprintf(line,sizeof(line),"\"%s\" /D /S /C \"%s\"",shell,command)>=(int)sizeof(line))goto fail;
    job=CreateJobObjectA(NULL,NULL);if(!job)goto fail;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;memset(&limits,0,sizeof(limits));limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if(!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits)))goto fail;
    if(!CreateProcessA(shell,line,NULL,NULL,TRUE,CREATE_NO_WINDOW|CREATE_SUSPENDED,NULL,NULL,&si,&pi))goto fail;
    if(!AssignProcessToJobObject(job,pi.hProcess)){TerminateProcess(pi.hProcess,1);goto fail;}
    ResumeThread(pi.hThread);CloseHandle(write_pipe);write_pipe=NULL;CloseHandle(input);input=NULL;
    for(;;) {
        DWORD available=0,read=0,exit_code=0;unsigned char buffer[1024];
        if(PeekNamedPipe(read_pipe,NULL,0,NULL,&available,NULL)&&available) {
            if(ReadFile(read_pipe,buffer,available>sizeof(buffer)?sizeof(buffer):available,&read,NULL)&&read) {
                size_t take=read;if(take>cap-*length){take=cap-*length;truncated=1;}
                memcpy(output+*length,buffer,take);*length+=take;continue;
            }
        }
        if(WaitForSingleObject(pi.hProcess,0)==WAIT_OBJECT_0&&GetExitCodeProcess(pi.hProcess,&exit_code)) { status=(int)exit_code;break; }
        if(bp_now()>=deadline){TerminateJobObject(job,124);WaitForSingleObject(pi.hProcess,5000);status=124;break;}
        bp_sleep(10);
    }
    CloseHandle(pi.hThread);CloseHandle(pi.hProcess);CloseHandle(read_pipe);CloseHandle(job);
    return truncated?125:status;
fail:
    if(pi.hThread)CloseHandle(pi.hThread);if(pi.hProcess)CloseHandle(pi.hProcess);
    if(read_pipe)CloseHandle(read_pipe);if(write_pipe)CloseHandle(write_pipe);if(input)CloseHandle(input);if(job)CloseHandle(job);
    return 126;
#else
    int pipes[2];if(pipe(pipes))return 126;pid_t child=fork();
    if(child<0){close(pipes[0]);close(pipes[1]);return 126;}
    if(!child) {
        setpgid(0,0);int input=open("/dev/null",O_RDONLY);if(input>=0){dup2(input,0);close(input);}
        dup2(pipes[1],1);dup2(pipes[1],2);close(pipes[0]);close(pipes[1]);
        execl("/bin/sh","sh","-c",command,(char*)NULL);_exit(126);
    }
    close(pipes[1]);setpgid(child,child);fcntl(pipes[0],F_SETFL,O_NONBLOCK);
    int done=0,eof=0,code=0;
    while(!done||!eof) {
        unsigned char buffer[1024];ssize_t n=read(pipes[0],buffer,sizeof(buffer));
        if(n>0) {
            size_t take=(size_t)n;if(take>cap-*length){take=cap-*length;truncated=1;}
            memcpy(output+*length,buffer,take);*length+=take;
        } else if(n==0)eof=1;
        if(!done&&waitpid(child,&code,WNOHANG)==child)done=1;
        if(bp_now()>=deadline){kill(-child,SIGKILL);if(!done)while(waitpid(child,&code,0)<0&&errno==EINTR){}status=124;break;}
        if(n<=0)bp_sleep(10);
    }
    close(pipes[0]);if(!status)status=WIFEXITED(code)?WEXITSTATUS(code):128+(WIFSIGNALED(code)?WTERMSIG(code):0);
    return truncated?125:status;
#endif
}
