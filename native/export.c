#include "bp.h"
#include <openssl/pem.h>
#include <string.h>
#include <stdlib.h>
#ifndef _WIN32
#include <sys/stat.h>
#endif

static const unsigned char footer_magic[8]={'B','P','A','G','E','N','T','2'};
#ifdef BP_WITH_TEMPLATES
extern const unsigned char bp_template_windows[], bp_template_linux[];
extern const size_t bp_template_windows_size, bp_template_linux_size;
#endif
#ifdef BP_WITH_TEMPLATES
static int append_pem(unsigned char **p,unsigned char *end,int kind,void *object) {
    BIO *bio=BIO_new(BIO_s_mem());char *data=NULL;long n;int ok=0;
    if(!bio)return 0;
    if(kind==1) { if(!PEM_write_bio_PrivateKey(bio,object,NULL,NULL,0,NULL,NULL))goto done; }
    else if(!PEM_write_bio_X509(bio,object))goto done;
    n=BIO_get_mem_data(bio,&data);if(n<=0||n>8192||end-*p<n+2)goto done;
    (*p)[0]=(unsigned char)(n>>8);(*p)[1]=(unsigned char)n;memcpy(*p+2,data,n);*p+=n+2;ok=1;
done:BIO_free(bio);return ok;
}
#endif
int bp_write_agent(bp_identity *identity,const char *target,const char *output,const char *host,
                   uint16_t port,uint32_t interval,char client_id[33]) {
#ifndef BP_WITH_TEMPLATES
    (void)identity;(void)target;(void)output;(void)host;(void)port;(void)interval;(void)client_id;
    fprintf(stderr,"This build does not contain client templates.\n");return 0;
#else
    const unsigned char *binary=NULL;size_t size=0;bp_agent agent={0};int ok=0;FILE *file=NULL;
    unsigned char config[BP_CONFIG_SIZE]={0},footer[16]={0},*p=config;
    if(!strcmp(target,"windows-x64")){binary=bp_template_windows;size=bp_template_windows_size;}
    else if(!strcmp(target,"linux-x64")){binary=bp_template_linux;size=bp_template_linux_size;}
    else { fprintf(stderr,"Target must be windows-x64 or linux-x64.\n");return 0; }
    if(strlen(host)>255||!port||interval<100||interval>60000||!bp_agent_certificate(identity,&agent))goto done;
    memcpy(p,"BPCFG2\0\0",8);p+=8;*p++=(unsigned char)(port>>8);*p++=(unsigned char)port;
    bp_put64(p,interval);p+=8;memcpy(p,agent.client,16);p+=16;memcpy(p,agent.server_pin,32);p+=32;
    memcpy(p,host,strlen(host));p+=256;
    if(!append_pem(&p,config+sizeof(config),1,agent.key)||!append_pem(&p,config+sizeof(config),2,agent.cert)
       ||!append_pem(&p,config+sizeof(config),2,agent.ca))goto done;
    memcpy(footer,footer_magic,8);bp_put64(footer+8,BP_CONFIG_SIZE);
    file=bp_private_create(output);if(!file) { perror("Create client (will not overwrite)");goto done; }
    ok=fwrite(binary,1,size,file)==size&&fwrite(config,1,sizeof(config),file)==sizeof(config)
       &&fwrite(footer,1,sizeof(footer),file)==sizeof(footer);
    if(fclose(file))ok=0;file=NULL;
#ifndef _WIN32
    if(ok&&chmod(output,0700))ok=0;
#endif
    if(ok)bp_hex(agent.client,16,client_id);
done:
    if(file)fclose(file);bp_agent_free(&agent);OPENSSL_cleanse(config,sizeof(config));return ok;
#endif
}
static void *read_pem(const unsigned char **p,const unsigned char *end,int key) {
    if(end-*p<2)return NULL;unsigned n=((unsigned)(*p)[0]<<8)|(*p)[1];*p+=2;
    if(!n||n>8192||end-*p<n)return NULL;
    BIO *bio=BIO_new_mem_buf(*p,n);if(!bio)return NULL;
    void *object=key?(void*)PEM_read_bio_PrivateKey(bio,NULL,NULL,NULL):(void*)PEM_read_bio_X509(bio,NULL,NULL,NULL);
    BIO_free(bio);*p+=n;return object;
}
int bp_read_agent(const char *path,bp_agent *agent) {
    FILE *file=fopen(path,"rb");unsigned char footer[16],config[BP_CONFIG_SIZE];int result=0;
    memset(agent,0,sizeof(*agent));if(!file)return -1;
    if(fseek(file,-16,SEEK_END)||fread(footer,1,16,file)!=16)goto done;
    if(memcmp(footer,footer_magic,8))goto done;
    result=-1;
    if(bp_get64(footer+8)!=BP_CONFIG_SIZE||fseek(file,-(long)(BP_CONFIG_SIZE+16),SEEK_END)
       ||fread(config,1,sizeof(config),file)!=sizeof(config)||memcmp(config,"BPCFG2\0\0",8))goto done;
    const unsigned char *p=config+8,*end=config+sizeof(config);
    agent->port=(uint16_t)(((unsigned)p[0]<<8)|p[1]);p+=2;
    uint64_t interval=bp_get64(p);p+=8;if(interval<100||interval>60000||!agent->port)goto done;
    agent->interval=(uint32_t)interval;memcpy(agent->client,p,16);p+=16;memcpy(agent->server_pin,p,32);p+=32;
    memcpy(agent->host,p,256);p+=256;if(!memchr(agent->host,0,256)||!agent->host[0])goto done;
    agent->key=read_pem(&p,end,1);agent->cert=read_pem(&p,end,0);agent->ca=read_pem(&p,end,0);
    if(!agent->key||!agent->cert||!agent->ca||X509_check_private_key(agent->cert,agent->key)!=1)goto done;
    result=1;
done:
    fclose(file);OPENSSL_cleanse(config,sizeof(config));if(result<0)bp_agent_free(agent);return result;
}
