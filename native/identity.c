#include "bp.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <errno.h>

void bp_put64(unsigned char *p, uint64_t v) { for(int i=7;i>=0;i--) { p[i]=(unsigned char)v; v>>=8; } }
uint64_t bp_get64(const unsigned char *p) { uint64_t v=0; for(int i=0;i<8;i++) v=(v<<8)|p[i]; return v; }
void bp_hex(const unsigned char *src,size_t n,char *out) {
    static const char h[]="0123456789abcdef";
    for(size_t i=0;i<n;i++) { out[i*2]=h[src[i]>>4];out[i*2+1]=h[src[i]&15]; }out[n*2]=0;
}
int bp_unhex(const char *s,unsigned char *out,size_t n) {
    if(strlen(s)!=n*2)return 0;
    for(size_t i=0;i<n;i++) {
        unsigned v=0;
        for(int j=0;j<2;j++) { char c=s[i*2+j];unsigned d;
            if(c>='0'&&c<='9')d=c-'0';else if(c>='a'&&c<='f')d=c-'a'+10;else return 0;
            v=(v<<4)|d;
        }out[i]=(unsigned char)v;
    }return 1;
}
static EVP_PKEY *new_key(void) { return EVP_PKEY_Q_keygen(NULL,NULL,"EC","prime256v1"); }
static int extension(X509 *cert,X509 *issuer,int nid,const char *value) {
    X509V3_CTX ctx; X509V3_set_ctx(&ctx,issuer,cert,NULL,NULL,0);
    X509_EXTENSION *ext=X509V3_EXT_conf_nid(NULL,&ctx,nid,(char*)value);
    if(!ext)return 0;int ok=X509_add_ext(cert,ext,-1);X509_EXTENSION_free(ext);return ok;
}
static X509 *new_cert(EVP_PKEY *key,X509 *issuer,EVP_PKEY *signer,const char *name,int role) {
    X509 *cert=X509_new();unsigned char serial[16];ASN1_INTEGER *number=NULL;BIGNUM *bn=NULL;
    if(!cert||RAND_bytes(serial,sizeof(serial))!=1)goto fail;
    serial[0]&=0x7f;serial[0]|=1;bn=BN_bin2bn(serial,sizeof(serial),NULL);number=BN_to_ASN1_INTEGER(bn,NULL);
    if(!number||!X509_set_version(cert,2)||!X509_set_serialNumber(cert,number)||!X509_set_pubkey(cert,key))goto fail;
    if(!X509_gmtime_adj(X509_getm_notBefore(cert),-300)||!X509_gmtime_adj(X509_getm_notAfter(cert),31536000L))goto fail;
    X509_NAME *subject=X509_get_subject_name(cert);
    if(!X509_NAME_add_entry_by_txt(subject,"CN",MBSTRING_ASC,(const unsigned char*)name,-1,-1,0))goto fail;
    if(!X509_set_issuer_name(cert,issuer?X509_get_subject_name(issuer):subject))goto fail;
    if(!extension(cert,issuer?issuer:cert,NID_basic_constraints,role==0?"critical,CA:TRUE,pathlen:0":"critical,CA:FALSE"))goto fail;
    if(!extension(cert,issuer?issuer:cert,NID_key_usage,role==0?"critical,keyCertSign,cRLSign":"critical,digitalSignature"))goto fail;
    if(role&&!extension(cert,issuer,NID_ext_key_usage,role==1?"serverAuth":"clientAuth"))goto fail;
    if(!X509_sign(cert,signer?signer:key,EVP_sha256()))goto fail;
    BN_free(bn);ASN1_INTEGER_free(number);return cert;
fail:
    BN_free(bn);ASN1_INTEGER_free(number);X509_free(cert);return NULL;
}
int bp_identity_load(bp_identity *id,const char *path) {
    memset(id,0,sizeof(*id));FILE *file=fopen(path,"rb");
    if(file) {
        id->ca_key=PEM_read_PrivateKey(file,NULL,NULL,NULL);id->ca=PEM_read_X509(file,NULL,NULL,NULL);
        id->server_key=PEM_read_PrivateKey(file,NULL,NULL,NULL);id->server_cert=PEM_read_X509(file,NULL,NULL,NULL);
        fclose(file);
    } else {
        if(errno!=ENOENT)return 0;
        id->ca_key=new_key();if(!id->ca_key)goto fail;
        id->ca=new_cert(id->ca_key,NULL,NULL,"BrushPass native CA",0);id->server_key=new_key();
        if(!id->ca||!id->server_key)goto fail;
        id->server_cert=new_cert(id->server_key,id->ca,id->ca_key,"BrushPass native server",1);
        if(!id->server_cert)goto fail;
        file=bp_private_create(path);if(!file)goto fail;
        int ok=PEM_write_PrivateKey(file,id->ca_key,NULL,NULL,0,NULL,NULL)&&PEM_write_X509(file,id->ca)
            &&PEM_write_PrivateKey(file,id->server_key,NULL,NULL,0,NULL,NULL)&&PEM_write_X509(file,id->server_cert);
        if(fclose(file))ok=0;if(!ok)goto fail;
        printf("Created identity credential: %s (contains private keys; keep private)\n",path);
    }
    if(!id->ca_key||!id->ca||!id->server_key||!id->server_cert
       ||X509_check_private_key(id->ca,id->ca_key)!=1||X509_check_private_key(id->server_cert,id->server_key)!=1
       ||X509_verify(id->ca,id->ca_key)!=1||X509_verify(id->server_cert,id->ca_key)!=1)goto fail;
    return 1;
fail:bp_identity_free(id);return 0;
}
void bp_identity_free(bp_identity *id) {
    EVP_PKEY_free(id->ca_key);EVP_PKEY_free(id->server_key);X509_free(id->ca);X509_free(id->server_cert);memset(id,0,sizeof(*id));
}
int bp_agent_certificate(bp_identity *id,bp_agent *agent) {
    char name[33];if(RAND_bytes(agent->client,16)!=1)return 0;bp_hex(agent->client,16,name);
    agent->key=new_key();if(!agent->key)return 0;
    agent->cert=new_cert(agent->key,id->ca,id->ca_key,name,2);
    if(!agent->cert||!X509_up_ref(id->ca))return 0;agent->ca=id->ca;
    return bp_certificate_pin(id->server_cert,agent->server_pin);
}
int bp_certificate_pin(X509 *cert,unsigned char pin[32]) {
    unsigned n=0;return cert&&X509_digest(cert,EVP_sha256(),pin,&n)==1&&n==32;
}
SSL_CTX *bp_tls_context(X509 *ca,X509 *cert,EVP_PKEY *key,int server) {
    SSL_CTX *ctx=SSL_CTX_new(TLS_method());if(!ctx)return NULL;
    if(!SSL_CTX_set_min_proto_version(ctx,TLS1_3_VERSION)||!SSL_CTX_set_max_proto_version(ctx,TLS1_3_VERSION)
       ||!SSL_CTX_use_certificate(ctx,cert)||!SSL_CTX_use_PrivateKey(ctx,key)||!SSL_CTX_check_private_key(ctx)
       ||!X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx),ca)) { SSL_CTX_free(ctx);return NULL; }
    SSL_CTX_set_verify(ctx,server?(SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT):SSL_VERIFY_PEER,NULL);
    SSL_CTX_set_session_cache_mode(ctx,SSL_SESS_CACHE_OFF);SSL_CTX_set_options(ctx,SSL_OP_NO_TICKET);
    SSL_CTX_set_num_tickets(ctx,0);SSL_CTX_set_max_early_data(ctx,0);
    if(!bp_register_extension(ctx)) { SSL_CTX_free(ctx);return NULL; }
    return ctx;
}
int bp_tls_authorized(SSL *ssl,const unsigned char *client,const unsigned char *pin) {
    if(SSL_get_verify_result(ssl)!=X509_V_OK||SSL_session_reused(ssl)||SSL_version(ssl)!=TLS1_3_VERSION)return 0;
    X509 *cert=SSL_get1_peer_certificate(ssl);if(!cert)return 0;int ok=0;
    if(pin) { unsigned char actual[32];ok=bp_certificate_pin(cert,actual)&&CRYPTO_memcmp(pin,actual,32)==0; }
    else if(client) {
        char name[128],expected[33];bp_hex(client,16,expected);
        int n=X509_NAME_get_text_by_NID(X509_get_subject_name(cert),NID_commonName,name,sizeof(name));
        ok=n==32&&memcmp(name,expected,32)==0;
    }
    X509_free(cert);return ok;
}
int bp_export_keys(SSL *ssl,bp_exchange *ex) {
    unsigned char context[48];const char label[]="EXPORTER-BrushPass-v2";
    memcpy(context,ex->client,16);memcpy(context+16,ex->nonce,16);memcpy(context+32,ex->sid,16);
    return SSL_export_keying_material(ssl,ex->keys,64,label,sizeof(label)-1,context,sizeof(context),1);
}
void bp_agent_free(bp_agent *a) { EVP_PKEY_free(a->key);X509_free(a->cert);X509_free(a->ca);OPENSSL_cleanse(a,sizeof(*a)); }
