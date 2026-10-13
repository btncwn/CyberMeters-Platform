/* SPDX-License-Identifier: Apache-2.0
 * Test fixture only. Binds IPv4 loopback exclusively; never shipped in image.
 */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static unsigned char ocsp_der[65536];
static long ocsp_len;
static SSL_CTX *alternate_ctx;
static const char *alternate_hostname;
static int choose_sni(SSL *ssl,int *alert,void *unused) {
    (void)alert;(void)unused;
    const char *requested=SSL_get_servername(ssl,TLSEXT_NAMETYPE_host_name);
    if(requested&&alternate_ctx&&!strcmp(requested,alternate_hostname))SSL_set_SSL_CTX(ssl,alternate_ctx);
    return SSL_TLSEXT_ERR_OK;
}
static int choose_alpn(SSL *ssl,const unsigned char **out,unsigned char *outlen,
                       const unsigned char *in,unsigned int inlen,void *unused) {
    (void)ssl;(void)unused;
    static const unsigned char h2[]={2,'h','2'};
    return SSL_select_next_proto((unsigned char **)out,outlen,h2,sizeof(h2),in,inlen)==OPENSSL_NPN_NEGOTIATED
      ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_NOACK;
}
static int staple(SSL *ssl,void *unused) {
    (void)unused;
    unsigned char *copy=OPENSSL_malloc((size_t)ocsp_len);
    if(!copy)return SSL_TLSEXT_ERR_ALERT_FATAL;
    memcpy(copy,ocsp_der,(size_t)ocsp_len);
    if(!SSL_set_tlsext_status_ocsp_resp(ssl,copy,(int)ocsp_len)) {
        OPENSSL_free(copy);return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    return SSL_TLSEXT_ERR_OK;
}
int main(int argc,char **argv) {
    if(argc<5)return 2;
    const char *protocol=argv[4];SSL_CTX *ctx=NULL;
    signal(SIGPIPE,SIG_IGN);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();OpenSSL_add_all_algorithms();
    const SSL_METHOD *m=!strcmp(protocol,"ssl2")?SSLv2_server_method():
      !strcmp(protocol,"ssl3")?SSLv3_server_method():!strcmp(protocol,"tls1")?TLSv1_server_method():
      !strcmp(protocol,"tls1_1")?TLSv1_1_server_method():TLSv1_2_server_method();
    ctx=SSL_CTX_new(m);
#else
    OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG,NULL);ctx=SSL_CTX_new(TLS_server_method());
    int v=(!strcmp(protocol,"tls1_3")||!strcmp(protocol,"tls1_3_early"))?TLS1_3_VERSION:TLS1_2_VERSION;
    SSL_CTX_set_min_proto_version(ctx,v);
    SSL_CTX_set_max_proto_version(ctx,!strcmp(protocol,"both")?TLS1_3_VERSION:v);
#endif
    if(!ctx||!SSL_CTX_use_certificate_chain_file(ctx,argv[2])||!SSL_CTX_use_PrivateKey_file(ctx,argv[3],SSL_FILETYPE_PEM))return 3;
    if(argc>9) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        alternate_ctx=SSL_CTX_new(SSLv23_server_method());
#else
        alternate_ctx=SSL_CTX_new(TLS_server_method());
#endif
        if(!alternate_ctx||!SSL_CTX_use_certificate_chain_file(alternate_ctx,argv[7])||
           !SSL_CTX_use_PrivateKey_file(alternate_ctx,argv[8],SSL_FILETYPE_PEM))return 7;
        alternate_hostname=argv[9];
        SSL_CTX_set_tlsext_servername_callback(ctx,choose_sni);
    }
    SSL_CTX_set_alpn_select_cb(ctx,choose_alpn,NULL);
    if(argc>6&&strcmp(argv[6],"-")) {
        FILE *source=fopen(argv[6],"rb");
        if(!source)return 6;
        ocsp_len=(long)fread(ocsp_der,1,sizeof(ocsp_der),source);
        int oversized=fgetc(source)!=EOF;
        fclose(source);
        if(ocsp_len<=0||oversized)return 6;
        SSL_CTX_set_tlsext_status_cb(ctx,staple);
    }
    SSL_CTX_set_cipher_list(ctx,argc>5?argv[5]:"ALL:eNULL:!PSK:!SRP");
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_CTX_set_ecdh_auto(ctx,1);
#else
    SSL_CTX_set_security_level(ctx,0);
#endif
    unsigned char sid[]={1,2,3};SSL_CTX_set_session_id_context(ctx,sid,sizeof(sid));
    SSL_CTX_set_session_cache_mode(ctx,SSL_SESS_CACHE_SERVER);
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    SSL_CTX_set_num_tickets(ctx,2);
    if(!strcmp(protocol,"tls1_3_early"))SSL_CTX_set_max_early_data(ctx,1024);
#endif
    int fd=socket(AF_INET,SOCK_STREAM,0),yes=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
    struct sockaddr_in address={0};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons((unsigned short)atoi(argv[1]));
    if(bind(fd,(struct sockaddr *)&address,sizeof(address))||listen(fd,8))return 4;
    for(;;) {
        int peer=accept(fd,NULL,NULL);if(peer<0)return 5;
        SSL *ssl=SSL_new(ctx);SSL_set_fd(ssl,peer);
        if(SSL_accept(ssl)==1) {unsigned char byte;SSL_read(ssl,&byte,1);}
        SSL_free(ssl);close(peer);
    }
}
