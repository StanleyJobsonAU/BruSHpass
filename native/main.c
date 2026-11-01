#include "bp.h"
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#include <sys/select.h>
#endif

static volatile sig_atomic_t interrupted=0;
static void interrupt_handler(int sig){(void)sig;interrupted=1;}
#ifndef BP_CLIENT_TEMPLATE
static void log_session(const char *event,const unsigned char *id) {
    char hex[33];bp_hex(id,16,hex);printf("\n[%s] client=%s\n",event,hex);fflush(stdout);
}
static void handle_server(bp_server *server,bp_socket sock) {
    bp_exchange ex;memset(&ex,0,sizeof(ex));ex.server=server;ex.server_side=1;
    SSL *ssl=SSL_new(server->tls);int authenticated=0,new_frame=0;bp_session *session=NULL;
    if(!ssl)goto done;SSL_set_app_data(ssl,&ex);
    if(!SSL_set_fd(ssl,(int)sock))goto done;SSL_set_accept_state(ssl);
    if(!bp_tls_run(ssl,sock,0)||!ex.parsed||ex.failed||!bp_tls_authorized(ssl,ex.client,NULL))goto done;
    authenticated=1;bp_lock(&server->mutex);
    if(ex.opening) {
        if(!bp_export_keys(ssl,&ex)){bp_unlock(&server->mutex);goto done;}
        for(int i=0;i<BP_CLIENTS;i++)if(server->sessions[i].active&&!memcmp(server->sessions[i].client,ex.client,16)){session=&server->sessions[i];break;}
        if(!session)for(int i=0;i<BP_CLIENTS;i++)if(!server->sessions[i].active){session=&server->sessions[i];break;}
        if(!session){bp_unlock(&server->mutex);goto done;}
        if(session->active)log_session("session replaced; old queues discarded",ex.client);
        bp_session_clear(session);session->active=1;session->next_id=1;session->last_seen=bp_now();
        memcpy(session->client,ex.client,16);memcpy(session->sid,ex.sid,16);memcpy(session->keys,ex.keys,64);
        log_session("session established",ex.client);
    } else {
        session=ex.session;
        if(!session||!bp_commit(session,&ex,&new_frame)){bp_unlock(&server->mutex);goto done;}
        if(new_frame) {
            char hex[33];bp_hex(ex.client,16,hex);
            if(ex.frame.kind==BP_OUTPUT) {
                printf("\n[%s command=%llu chunk=%u]\n",hex,(unsigned long long)ex.frame.command,ex.frame.chunk);
                bp_print_bytes(ex.frame.body,ex.frame.length);
            } else if(ex.frame.kind==BP_DONE) {
                if(session->running_command==ex.frame.command)session->running_command=0;
                uint32_t code=((uint32_t)ex.frame.body[0]<<24)|((uint32_t)ex.frame.body[1]<<16)|((uint32_t)ex.frame.body[2]<<8)|ex.frame.body[3];
                printf("\n[%s command=%llu complete exit=%u]\n",hex,(unsigned long long)ex.frame.command,code);fflush(stdout);
            }
        }
    }
    bp_unlock(&server->mutex);
    if(bp_tls_run(ssl,sock,1))goto success;
done:
    /* Only an authenticated peer can cause its existing session to be removed. */
    if(authenticated) {
        bp_lock(&server->mutex);
        if(session&&session->active&&!memcmp(session->sid,ex.sid,16)){log_session("exchange failed; session discarded",session->client);bp_session_clear(session);}
        bp_unlock(&server->mutex);
    }
success:
    SSL_free(ssl);bp_socket_close(sock);OPENSSL_cleanse(&ex,sizeof(ex));
}
#ifdef _WIN32
static unsigned __stdcall server_worker(void *arg) {
#else
static void *server_worker(void *arg) {
#endif
    bp_server *server=arg;
    while(!interrupted) {
        bp_lock(&server->mutex);int stopping=server->stop;bp_unlock(&server->mutex);
        if(stopping)break;
        fd_set read;struct timeval tv={0,200000};FD_ZERO(&read);FD_SET(server->listener,&read);
        if(select((int)server->listener+1,&read,NULL,NULL,&tv)>0) {
            bp_socket sock=accept(server->listener,NULL,NULL);if(sock!=BP_BAD_SOCKET)handle_server(server,sock);
        }
        bp_lock(&server->mutex);
        for(int i=0;i<BP_CLIENTS;i++)if(server->sessions[i].active&&bp_now()-server->sessions[i].last_seen>60000) {
            log_session("session expired; queues discarded",server->sessions[i].client);bp_session_clear(&server->sessions[i]);
        }
        bp_unlock(&server->mutex);
    }
    return 0;
}
#endif
static int client_exchange(bp_agent *agent,SSL_CTX *ctx,bp_session *session,bp_frame *incoming,int *is_new) {
    bp_socket sock=bp_connect(agent->host,agent->port);if(sock==BP_BAD_SOCKET)return 0;
    bp_exchange ex;memset(&ex,0,sizeof(ex));int ok=0;SSL *ssl=NULL;
    if(session->active){if(!bp_prepare_data(&ex,session))goto done;}
    else if(!bp_prepare_open(&ex,agent->client))goto done;
    ssl=SSL_new(ctx);if(!ssl)goto done;SSL_set_app_data(ssl,&ex);if(!SSL_set_fd(ssl,(int)sock))goto done;SSL_set_connect_state(ssl);
    if(!bp_tls_run(ssl,sock,0)||!ex.parsed||ex.failed||!bp_tls_authorized(ssl,NULL,agent->server_pin))goto done;
    if(ex.opening&&!bp_export_keys(ssl,&ex))goto done;
    if(!bp_tls_run(ssl,sock,1))goto done;
    if(ex.opening) {
        bp_session_clear(session);session->active=1;session->next_id=1;session->last_seen=bp_now();
        memcpy(session->client,agent->client,16);memcpy(session->sid,ex.sid,16);memcpy(session->keys,ex.keys,64);*is_new=0;
        puts("Authenticated session established; fresh session keys ready.");fflush(stdout);
    } else { if(!bp_commit(session,&ex,is_new))goto done;*incoming=ex.frame; }
    ok=1;
done:SSL_free(ssl);bp_socket_close(sock);OPENSSL_cleanse(&ex,sizeof(ex));return ok;
}
static int run_agent(bp_agent *agent) {
    char initial_directory[4096];if(!bp_cwd(initial_directory,sizeof(initial_directory)))return 1;
    SSL_CTX *ctx=bp_tls_context(agent->ca,agent->cert,agent->key,0);bp_session *s=calloc(1,sizeof(*s));
    if(!ctx||!s){SSL_CTX_free(ctx);free(s);return 1;}
    char id[33];bp_hex(agent->client,16,id);
    printf("BruSHpass native client %s\nConnecting to %s:%u. Remote commands run as this account. Ctrl+C stops.\n",id,agent->host,agent->port);fflush(stdout);
    unsigned failures=0;
    while(!interrupted) {
        bp_frame received={0};int fresh=0;
        if(!client_exchange(agent,ctx,s,&received,&fresh)) {
            if(s->active)puts("Connection failed: session, keys, and pending results discarded.");
            bp_session_clear(s);
            if(!bp_chdir(initial_directory)){puts("Cannot restore initial working directory; stopping.");break;}
            if(failures<5)failures++;unsigned delay=1000u<<failures;
            if(delay>10000)delay=10000;
            printf("Connection/authentication attempt failed; retrying in %u ms.\n",delay);fflush(stdout);bp_sleep(delay);continue;
        }
        failures=0;
        if(fresh&&received.kind==BP_COMMAND) {
            char command[BP_BODY+1];unsigned char output[16384];size_t n=0;
            memcpy(command,received.body,received.length);command[received.length]=0;
            printf("Executing command %llu\n",(unsigned long long)received.command);fflush(stdout);
            int code=bp_execute(command,output,sizeof(output),&n);unsigned chunk=0;
            for(size_t at=0;at<n;at+=BP_BODY) {
                bp_frame f={0};f.kind=BP_OUTPUT;f.command=received.command;f.chunk=chunk++;
                f.length=(uint16_t)((n-at)>BP_BODY?BP_BODY:n-at);memcpy(f.body,output+at,f.length);
                if(!bp_enqueue(s,&f)){bp_session_clear(s);break;}
            }
            if(s->active) {
                bp_frame f={0};f.kind=BP_DONE;f.command=received.command;f.chunk=chunk;f.length=4;
                uint32_t c=(uint32_t)code;for(int i=3;i>=0;i--){f.body[i]=(unsigned char)c;c>>=8;}
                if(!bp_enqueue(s,&f))bp_session_clear(s);
            }
            OPENSSL_cleanse(command,sizeof(command));OPENSSL_cleanse(output,sizeof(output));
        }
        OPENSSL_cleanse(&received,sizeof(received));bp_sleep(s->count?100:agent->interval);
    }
    bp_session_clear(s);free(s);SSL_CTX_free(ctx);return 0;
}
#ifndef BP_CLIENT_TEMPLATE
static void help(void) {
    puts("Commands:\n  export-client <windows-x64|linux-x64> <output-path> [advertised-host]\n  clients\n  use <client-id>\n  send <client-id> <shell-command>\n  <shell-command>                 send to selected client\n  drop <client-id>                discard session and queued commands\n  help\n  quit");
}
static char *word(char **line) {
    char *p=*line;while(*p==' '||*p=='\t')p++;if(!*p){*line=p;return NULL;}
    char *start=p;
    if(*p=='"') { start=++p;while(*p&&*p!='"')p++; }
    else while(*p&&*p!=' '&&*p!='\t')p++;
    if(*p)*p++=0;*line=p;return start;
}
static bp_session *find_client(bp_server *s,const char *id) {
    unsigned char raw[16];if(!id||!bp_unhex(id,raw,16))return NULL;
    for(int i=0;i<BP_CLIENTS;i++)if(s->sessions[i].active&&!memcmp(s->sessions[i].client,raw,16))return &s->sessions[i];return NULL;
}
static int run_server(const char *interface,uint16_t port,const char *identity_path) {
    bp_server *server=calloc(1,sizeof(*server));if(!server)return 1;server->listener=BP_BAD_SOCKET;int result=1;
    bp_mutex_init(&server->mutex);server->port=port;
    if(!bp_interface(interface,server->address)){fprintf(stderr,"No IPv4 interface/address matches %s\n",interface);goto done;}
    if(!bp_identity_load(&server->identity,identity_path)){fprintf(stderr,"Cannot load/create identity credential.\n");goto done;}
    server->tls=bp_tls_context(server->identity.ca,server->identity.server_cert,server->identity.server_key,1);
    if(!server->tls){fprintf(stderr,"TLS context initialization failed.\n");goto done;}
    server->listener=bp_listen(server->address,port);if(server->listener==BP_BAD_SOCKET){fprintf(stderr,"Cannot bind %s:%u\n",server->address,port);goto done;}
#ifdef _WIN32
    HANDLE thread=(HANDLE)_beginthreadex(NULL,0,server_worker,server,0,NULL);if(!thread)goto done;
#else
    pthread_t thread;if(pthread_create(&thread,NULL,server_worker,server))goto done;
#endif
    printf("BruSHpass native server on %s:%u; TLS 1.3/mTLS; memory-only sessions.\n",server->address,port);help();
    char line[2048],selected[33]={0};
    while(!interrupted) {
        printf("BruSHpass%s%s> ",selected[0]?"/":"",selected);fflush(stdout);
        if(!fgets(line,sizeof(line),stdin))break;
        size_t n=strlen(line);if(n&&line[n-1]!='\n'&&!feof(stdin)){int c;while((c=getchar())!='\n'&&c!=EOF){}puts("Input line too long.");continue;}
        while(n&&(line[n-1]=='\n'||line[n-1]=='\r'))line[--n]=0;if(!n)continue;
        char original[2048];memcpy(original,line,n+1);char *rest=line,*cmd=word(&rest);if(!cmd)continue;
        if(!strcmp(cmd,"quit")||!strcmp(cmd,"exit"))break;
        if(!strcmp(cmd,"help")){help();continue;}
        if(!strcmp(cmd,"export-client")) {
            char *target=word(&rest),*output=word(&rest),*host=word(&rest),id[33];
            if(!target||!output){puts("Usage: export-client <target> <output> [host]");continue;}
            if(!strcmp(server->address,"0.0.0.0")&&!host){puts("Specify an advertised host when binding 0.0.0.0.");continue;}
            if(bp_write_agent(&server->identity,target,output,host?host:server->address,port,1000,id))printf("Exported client %s to %s (contains its private identity).\n",id,output);
            else puts("Client export failed.");continue;
        }
        bp_lock(&server->mutex);
        if(!strcmp(cmd,"clients")) {
            for(int i=0;i<BP_CLIENTS;i++)if(server->sessions[i].active) {
                bp_session *s=&server->sessions[i];char id[33];bp_hex(s->client,16,id);
                printf("%s  last seen %llums ago  pending=%u\n",id,(unsigned long long)(bp_now()-s->last_seen),s->count);
            }
        } else if(!strcmp(cmd,"use")) {
            char *id=word(&rest);if(find_client(server,id))snprintf(selected,sizeof(selected),"%s",id);else puts("Client not connected.");
        } else if(!strcmp(cmd,"drop")) {
            bp_session *s=find_client(server,word(&rest));if(s){bp_session_clear(s);puts("Session discarded.");}else puts("Client not connected.");
        } else {
            char *id=selected,*command=original;
            if(!strcmp(cmd,"send")){id=word(&rest);while(*rest==' '||*rest=='\t')rest++;command=rest;}
            bp_session *s=find_client(server,id);size_t length=strlen(command);
            if(!s)puts("Select a connected client with use <id>, or send <id> <command>.");
            else if(!length||length>BP_BODY)puts("Command must contain 1 to 512 bytes.");
            else {
                bp_frame f={0};f.kind=BP_COMMAND;f.command=++server->command_counter;f.length=(uint16_t)length;memcpy(f.body,command,length);
                if(bp_enqueue(s,&f))printf("Queued command %llu.\n",(unsigned long long)f.command);else puts("Client queue is full.");
            }
        }
        bp_unlock(&server->mutex);OPENSSL_cleanse(original,sizeof(original));OPENSSL_cleanse(line,sizeof(line));
    }
    bp_lock(&server->mutex);server->stop=1;bp_unlock(&server->mutex);
#ifdef _WIN32
    WaitForSingleObject(thread,INFINITE);CloseHandle(thread);
#else
    pthread_join(thread,NULL);
#endif
    result=0;
done:
    bp_socket_close(server->listener);SSL_CTX_free(server->tls);bp_identity_free(&server->identity);
    OPENSSL_cleanse(server,sizeof(*server));free(server);return result;
}
#endif
int main(int argc,char **argv) {
    if(!bp_platform_init())return 1;signal(SIGINT,interrupt_handler);signal(SIGTERM,interrupt_handler);
#ifndef _WIN32
    signal(SIGPIPE,SIG_IGN);
#endif
    if(argc==2&&!strcmp(argv[1],"--self-test")){int ok=bp_selftest();bp_platform_cleanup();return ok?0:1;}
    char self[4096];bp_agent agent;int embedded=0;
    if(!bp_self_path(self,sizeof(self))||(embedded=bp_read_agent(self,&agent))<0){fputs("Invalid client provisioning footer.\n",stderr);return 1;}
    if(embedded) { int result=run_agent(&agent);bp_agent_free(&agent);bp_platform_cleanup();return result; }
#ifdef BP_CLIENT_TEMPLATE
    fputs("Unprovisioned client template: export a client from the BruSHpass server.\n",stderr);
    bp_platform_cleanup();return 1;
#else
    const char *interface="127.0.0.1",*identity="brushpass-identity.pem";unsigned long port=8443;
    for(int i=1;i<argc;i++) {
        if((!strcmp(argv[i],"-i")||!strcmp(argv[i],"--interface"))&&i+1<argc)interface=argv[++i];
        else if((!strcmp(argv[i],"-p")||!strcmp(argv[i],"--port"))&&i+1<argc){char *end;port=strtoul(argv[++i],&end,10);if(*end||!port||port>65535)return 2;}
        else if(!strcmp(argv[i],"--identity")&&i+1<argc)identity=argv[++i];
        else { puts("Usage: BruSHpass [-i <IPv4-address|interface>] [-p <port>] [--identity <credential.pem>]\n       BruSHpass --self-test");bp_platform_cleanup();return !strcmp(argv[i],"--help")?0:2; }
    }
    int result=run_server(interface,(uint16_t)port,identity);bp_platform_cleanup();return result;
#endif
}
