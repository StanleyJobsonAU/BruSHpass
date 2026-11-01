#include "bp.h"
#include <string.h>
#include <limits.h>
#include <stdlib.h>

#define HEADER 47
#define FRAME 31
static const unsigned char magic[4]={'B','P','2',0};
static void put16(unsigned char *p,unsigned v) { p[0]=(unsigned char)(v>>8);p[1]=(unsigned char)v; }
static unsigned get16(const unsigned char *p) { return ((unsigned)p[0]<<8)|p[1]; }
static void put32(unsigned char *p,uint32_t v) { for(int i=3;i>=0;i--){p[i]=(unsigned char)v;v>>=8;} }
static uint32_t get32(const unsigned char *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static void header(unsigned char *out,int kind,const unsigned char *client,const unsigned char *sid,uint64_t seq,unsigned length) {
    memcpy(out,magic,4);out[4]=(unsigned char)kind;memcpy(out+5,client,16);memcpy(out+21,sid,16);
    bp_put64(out+37,seq);put16(out+45,length);
}
static int crypt(int encrypt,const unsigned char *key,uint64_t seq,const unsigned char *aad,
                 const unsigned char *input,size_t length,unsigned char *out) {
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();unsigned char nonce[12]={0};int n=0,total=0,ok=0;
    if(!ctx||length>BP_WIRE)goto end;bp_put64(nonce+4,seq);
    if(encrypt) {
        if(EVP_EncryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,key,nonce)!=1
           ||EVP_EncryptUpdate(ctx,NULL,&n,aad,HEADER)!=1||EVP_EncryptUpdate(ctx,out,&n,input,(int)length)!=1)goto end;
        total=n;if(EVP_EncryptFinal_ex(ctx,out+total,&n)!=1||n!=0||EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,16,out+total)!=1)goto end;
    } else {
        if(length<16||EVP_DecryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,key,nonce)!=1
           ||EVP_DecryptUpdate(ctx,NULL,&n,aad,HEADER)!=1||EVP_DecryptUpdate(ctx,out,&n,input,(int)length-16)!=1)goto end;
        total=n;if(EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,16,(void*)(input+length-16))!=1
           ||EVP_DecryptFinal_ex(ctx,out+total,&n)!=1||n!=0)goto end;
    }ok=1;
end:EVP_CIPHER_CTX_free(ctx);return ok;
}
int bp_prepare_open(bp_exchange *ex,const unsigned char client[16]) {
    memset(ex,0,sizeof(*ex));ex->opening=1;memcpy(ex->client,client,16);
    if(RAND_bytes(ex->nonce,16)!=1)return 0;
    header(ex->out,BP_OPEN,client,ex->sid,0,16);memcpy(ex->out+HEADER,ex->nonce,16);ex->outlen=HEADER+16;return 1;
}
int bp_prepare_data(bp_exchange *ex,bp_session *s) {
    bp_frame frame={0};unsigned char plain[BP_WIRE]={0};
    if(!s->active||s->tx==UINT64_MAX)return 0;
    if(s->count) {
        bp_frame *head=&s->queue[0];
        if(!ex->server_side||head->kind!=BP_COMMAND||!s->running_command||head->command==s->running_command) {
            frame=*head;
            if(ex->server_side&&head->kind==BP_COMMAND)s->running_command=head->command;
        }
    }
    frame.ack=s->accepted;
    if(frame.length>BP_BODY)return 0;
    memcpy(ex->client,s->client,16);memcpy(ex->sid,s->sid,16);memcpy(ex->keys,s->keys,64);ex->session=s;
    bp_put64(plain,frame.id);bp_put64(plain+8,frame.ack);bp_put64(plain+16,frame.command);
    put32(plain+24,frame.chunk);plain[28]=frame.kind;put16(plain+29,frame.length);memcpy(plain+FRAME,frame.body,frame.length);
    uint64_t seq=++s->tx;header(ex->out,BP_DATA,s->client,s->sid,seq,FRAME+frame.length+16);
    int ok=crypt(1,s->keys+(ex->server_side?32:0),seq,ex->out,plain,FRAME+frame.length,ex->out+HEADER);
    OPENSSL_cleanse(plain,sizeof(plain));if(!ok)return 0;ex->outlen=HEADER+FRAME+frame.length+16;return 1;
}
static int decode_data(bp_exchange *ex,const unsigned char *data,size_t n) {
    unsigned char plain[BP_WIRE]={0};int ok=0;
    if(n<HEADER+FRAME+16||n>BP_WIRE||get16(data+45)!=n-HEADER)return 0;
    if(memcmp(data+5,ex->client,16)||memcmp(data+21,ex->sid,16))return 0;
    ex->incoming_tx=bp_get64(data+37);if(!ex->incoming_tx)return 0;
    if(!crypt(0,ex->keys+(ex->server_side?0:32),ex->incoming_tx,data,data+HEADER,n-HEADER,plain))goto end;
    bp_frame *f=&ex->frame;memset(f,0,sizeof(*f));f->id=bp_get64(plain);f->ack=bp_get64(plain+8);f->command=bp_get64(plain+16);
    f->chunk=get32(plain+24);f->kind=plain[28];f->length=(uint16_t)get16(plain+29);
    if(f->length>BP_BODY||n!=(size_t)(HEADER+FRAME+f->length+16)||f->kind>BP_DONE)goto end;
    if(!f->id) { if(f->kind!=BP_POLL||f->length||f->command||f->chunk)goto end; }
    else if(!f->kind||!f->command)goto end;
    if(ex->server_side&&f->kind==BP_COMMAND)goto end;
    if(!ex->server_side&&(f->kind==BP_OUTPUT||f->kind==BP_DONE))goto end;
    if(f->kind==BP_COMMAND&&(f->length==0||memchr(plain+FRAME,0,f->length)))goto end;
    if(f->kind==BP_DONE&&f->length!=4)goto end;
    memcpy(f->body,plain+FRAME,f->length);ok=1;
end:OPENSSL_cleanse(plain,sizeof(plain));return ok;
}
static int add_ext(SSL *ssl,unsigned type,unsigned context,const unsigned char **out,size_t *len,
                   X509 *cert,size_t chain,int *alert,void *arg) {
    (void)type;(void)cert;(void)chain;(void)arg;
    bp_exchange *ex=SSL_get_app_data(ssl);
    if(!ex||context!=(unsigned)(ex->server_side?SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS:SSL_EXT_CLIENT_HELLO)
       ||!ex->outlen||ex->outlen>BP_WIRE) { *alert=SSL_AD_INTERNAL_ERROR;return -1; }
    *out=ex->out;*len=ex->outlen;return 1;
}
static int parse_ext(SSL *ssl,unsigned type,unsigned context,const unsigned char *data,size_t n,
                     X509 *cert,size_t chain,int *alert,void *arg) {
    (void)type;(void)cert;(void)chain;(void)arg;
    bp_exchange *ex=SSL_get_app_data(ssl);int ok=0;
    if(!ex||n<HEADER||n>BP_WIRE||memcmp(data,magic,4)||get16(data+45)!=n-HEADER)goto fail;
    if(context!=(unsigned)(ex->server_side?SSL_EXT_CLIENT_HELLO:SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS))goto fail;
    if(ex->parsed) { ok=n==ex->inlen&&!memcmp(data,ex->in,n);goto done; }
    if(ex->server_side) {
        if(data[4]==BP_OPEN) {
            unsigned char zero[16]={0};if(n!=HEADER+16||bp_get64(data+37)||memcmp(data+21,zero,16))goto fail;
            ex->opening=1;memcpy(ex->client,data+5,16);memcpy(ex->nonce,data+HEADER,16);
            if(RAND_bytes(ex->sid,16)!=1)goto fail;
            header(ex->out,BP_OPEN_REPLY,ex->client,ex->sid,0,16);memcpy(ex->out+HEADER,ex->nonce,16);ex->outlen=HEADER+16;ok=1;
        } else if(data[4]==BP_DATA) {
            bp_lock(&ex->server->mutex);
            for(int i=0;i<BP_CLIENTS;i++) {
                bp_session *s=&ex->server->sessions[i];
                if(s->active&&!memcmp(data+5,s->client,16)&&!memcmp(data+21,s->sid,16)) {
                    ex->session=s;memcpy(ex->client,s->client,16);memcpy(ex->sid,s->sid,16);memcpy(ex->keys,s->keys,64);
                    ok=decode_data(ex,data,n)&&ex->incoming_tx>s->rx&&bp_prepare_data(ex,s);break;
                }
            }
            bp_unlock(&ex->server->mutex);
        }
    } else if(ex->opening) {
        if(data[4]!=BP_OPEN_REPLY||n!=HEADER+16||bp_get64(data+37)||memcmp(data+5,ex->client,16)||memcmp(data+HEADER,ex->nonce,16))goto fail;
        memcpy(ex->sid,data+21,16);ok=1;
    } else if(data[4]==BP_DATA) ok=decode_data(ex,data,n);
done:
    if(ok) { if(!ex->parsed){memcpy(ex->in,data,n);ex->inlen=n;ex->parsed=1;}return 1; }
fail:
    if(ex)ex->failed=1;*alert=SSL_AD_ILLEGAL_PARAMETER;return 0;
}
int bp_register_extension(SSL_CTX *ctx) {
    return SSL_CTX_add_custom_ext(ctx,BP_EXT,SSL_EXT_TLS_ONLY|SSL_EXT_TLS1_3_ONLY|SSL_EXT_CLIENT_HELLO|SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                                  add_ext,NULL,NULL,parse_ext,NULL);
}
int bp_enqueue(bp_session *s,const bp_frame *frame) {
    if(s->count>=BP_QUEUE||s->next_id==UINT64_MAX||frame->length>BP_BODY)return 0;
    bp_frame *out=&s->queue[s->count++];*out=*frame;out->id=s->next_id++;return 1;
}
int bp_commit(bp_session *s,const bp_exchange *ex,int *new_frame) {
    const bp_frame *f=&ex->frame;*new_frame=0;
    if(!s->active||memcmp(s->sid,ex->sid,16)||ex->incoming_tx<=s->rx||f->ack>=s->next_id)return 0;
    if(f->id && f->id!=s->accepted && f->id!=s->accepted+1)return 0;
    if(f->id&&f->id==s->accepted) {
        const bp_frame *last=&s->last_received;
        if(f->kind!=last->kind||f->command!=last->command||f->chunk!=last->chunk||f->length!=last->length||memcmp(f->body,last->body,f->length))return 0;
    }
    if(s->count&&f->ack>s->queue[0].id)return 0;
    if(s->count&&f->ack==s->queue[0].id) {
        memmove(s->queue,s->queue+1,(s->count-1)*sizeof(bp_frame));s->count--;
        OPENSSL_cleanse(&s->queue[s->count],sizeof(bp_frame));
    }
    if(f->id>s->accepted) { s->accepted=f->id;s->last_received=*f;*new_frame=1; }
    s->rx=ex->incoming_tx;s->last_seen=bp_now();return 1;
}
void bp_session_clear(bp_session *s) { OPENSSL_cleanse(s,sizeof(*s)); }

int bp_selftest(void) {
    bp_session *server=calloc(1,sizeof(*server)),*client=calloc(1,sizeof(*client));
    bp_exchange outgoing={0},incoming={0};int ok=0,fresh=0;
    if(!server||!client)goto done;
    server->active=client->active=1;server->next_id=client->next_id=1;
    if(RAND_bytes(server->keys,64)!=1||RAND_bytes(server->client,16)!=1||RAND_bytes(server->sid,16)!=1)goto done;
    memcpy(client->keys,server->keys,64);memcpy(client->client,server->client,16);memcpy(client->sid,server->sid,16);
    bp_frame frame={0};frame.kind=BP_COMMAND;frame.command=1;frame.length=9;memcpy(frame.body,"echo test",9);
    if(!bp_enqueue(server,&frame))goto done;
    outgoing.server_side=1;if(!bp_prepare_data(&outgoing,server))goto done;
    memcpy(incoming.keys,client->keys,64);memcpy(incoming.client,client->client,16);memcpy(incoming.sid,client->sid,16);
    if(!decode_data(&incoming,outgoing.out,outgoing.outlen)||incoming.frame.length!=9||memcmp(incoming.frame.body,"echo test",9))goto done;
    if(!bp_commit(client,&incoming,&fresh)||!fresh||bp_commit(client,&incoming,&fresh))goto done;
    if(!bp_prepare_data(&outgoing,server)||!decode_data(&incoming,outgoing.out,outgoing.outlen)
       ||!bp_commit(client,&incoming,&fresh)||fresh)goto done;
    outgoing.out[outgoing.outlen-1]^=1;if(decode_data(&incoming,outgoing.out,outgoing.outlen))goto done;
    bp_exchange acknowledgment={0};if(!bp_prepare_data(&acknowledgment,client))goto done;
    bp_exchange receiver={0};receiver.server_side=1;memcpy(receiver.keys,server->keys,64);memcpy(receiver.client,server->client,16);memcpy(receiver.sid,server->sid,16);
    if(!decode_data(&receiver,acknowledgment.out,acknowledgment.outlen)||!bp_commit(server,&receiver,&fresh)||server->count)goto done;
    ok=1;
done:
    if(server){bp_session_clear(server);free(server);}if(client){bp_session_clear(client);free(client);}
    OPENSSL_cleanse(&outgoing,sizeof(outgoing));OPENSSL_cleanse(&incoming,sizeof(incoming));
    puts(ok?"Native protocol self-test passed (encryption, tamper, replay, deduplication, acknowledgment).":"Native protocol self-test FAILED.");return ok;
}
