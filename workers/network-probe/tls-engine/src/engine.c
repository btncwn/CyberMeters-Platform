/* SPDX-License-Identifier: Apache-2.0
 * Owned assessment adapter. Upstream OpenSSL performs Finished verification.
 * No DNS, sockets, process execution, application requests or certificate URL
 * fetches exist here. The network authority is the separately budgeted parent.
 */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include "sandbox.h"

#define CM_LEGACY (OPENSSL_VERSION_NUMBER < 0x10100000L)
#define FRAME_MAX 16384
#define RESULT_MAX 262144
#define BYTE_MAX 16777216
#define CHAIN_MAX 8
#ifndef CM_BUILD_ID
#error Build identity is required
#endif
#ifndef CM_ENGINE_FAMILY
#error Engine family is required
#endif

struct opts {
    const char *control, *protocol, *cipher, *group, *hostname, *alpn, *trust;
    unsigned timeout, max_connections;
};
static struct opts opt = {"handshake", "tls1_2", NULL, NULL, NULL, "none", NULL, 10000, 1};
static const char *protocols[] = {"ssl2","ssl3","tls1","tls1_1","tls1_2","tls1_3",NULL};
static const char *controls[] = {"catalog","handshake","certificate","renegotiation","resumption","fallback","compression","heartbleed","robot","ccs",NULL};
static const char *state="uncertain", *reason="engine_error";
static int finished, connected, aborted, sandboxed, peer_alert, reneg_completed=-1;
static unsigned connections, sent, received;
static uint64_t started, deadline;
static char trust_hash[65];
static time_t evaluated;
static X509_STORE *trust_store;
static int trust_loaded;
static unsigned char frame[FRAME_MAX];
static char json[RESULT_MAX];
static size_t json_len;
static const char *limitations[12];
static unsigned limitation_count;
static SSL_SESSION *new_session;
static uint32_t observed_early_data_max;
static int observed_early_data;

static uint64_t now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) _exit(3);
    return (uint64_t)t.tv_sec*1000+(unsigned)t.tv_nsec/1000000;
}
static void limit(const char *s) {
    unsigned i;
    for (i=0;i<limitation_count;i++) if (!strcmp(limitations[i],s)) return;
    if (limitation_count<12) limitations[limitation_count++]=s;
}
static int in_list(const char *s, const char **list) {
    for (;*list;list++) if (!strcmp(s,*list)) return 1;
    return 0;
}
static int identifier(const char *s, size_t max) {
    size_t n=strlen(s),i;
    if (!n||n>max) return 0;
    for (i=0;i<n;i++) if (!(isalnum((unsigned char)s[i])||s[i]=='_'||s[i]=='-')) return 0;
    return 1;
}
static int hostname(const char *s) {
    size_t n=strlen(s),i,label=0;
    if (!n||n>253||s[0]=='-'||s[n-1]=='-'||s[n-1]=='.') return 0;
    for (i=0;i<n;i++) {
        if (s[i]=='.') { if (!label||label>63||s[i-1]=='-'||s[i+1]=='-') return 0; label=0; }
        else { if (!(s[i]>='a'&&s[i]<='z')&&!(s[i]>='0'&&s[i]<='9')&&s[i]!='-') return 0; label++; }
    }
    return label&&label<=63;
}
static int number(const char *s,unsigned max,unsigned *out) {
    char *end; unsigned long n;
    if (!*s||*s=='-'||*s=='+') return 0;
    errno=0;n=strtoul(s,&end,10);
    if (errno||*end||!n||n>max) return 0;
    *out=(unsigned)n;return 1;
}
static int args(int argc,char **argv) {
    unsigned seen=0;
    if (!(argc&1)) return 0;
    for (int i=1;i<argc;i+=2) {
        unsigned bit=0;const char *k=argv[i],*v=argv[i+1];
        if (!strcmp(k,"--control")) { bit=1;opt.control=v; if(!in_list(v,controls))return 0; }
        else if(!strcmp(k,"--protocol")) {bit=2;opt.protocol=v;if(!in_list(v,protocols))return 0;}
        else if(!strcmp(k,"--cipher")) {bit=4;opt.cipher=v;if(!identifier(v,96))return 0;}
        else if(!strcmp(k,"--group")) {bit=8;opt.group=v;if(!identifier(v,64))return 0;}
        else if(!strcmp(k,"--hostname")) {bit=16;opt.hostname=v;if(!hostname(v))return 0;}
        else if(!strcmp(k,"--alpn")) {const char *a[]={"none","http1","h2-http1",NULL};bit=32;opt.alpn=v;if(!in_list(v,a))return 0;}
        else if(!strcmp(k,"--timeout-ms")) {bit=64;if(!number(v,25000,&opt.timeout))return 0;}
        else if(!strcmp(k,"--max-connections")) {bit=128;if(!number(v,64,&opt.max_connections))return 0;}
        else if(!strcmp(k,"--trust-bundle")) {bit=256;opt.trust=v;if(v[0]!='/'||strlen(v)>1024)return 0;}
        else return 0;
        if(seen&bit)return 0;
        seen|=bit;
    }
    return 1;
}
static void append(const char *fmt,...) {
    va_list ap;int n;
    va_start(ap,fmt);n=vsnprintf(json+json_len,sizeof(json)-json_len,fmt,ap);va_end(ap);
    if(n<0||(size_t)n>=sizeof(json)-json_len) _exit(4);
    json_len+=(size_t)n;
}
static const char *boolean(int n) {return n<0?"null":n?"true":"false";}
static int ready(int fd,short events) {
    struct pollfd p={fd,events,0};int r;uint64_t now=now_ms();
    if(now>=deadline) {reason="transport_timeout";return 0;}
    do {r=poll(&p,1,(int)(deadline-now));} while(r<0&&errno==EINTR&&(now=now_ms())<deadline);
    if(r<=0) {reason=r==0?"transport_timeout":"malformed_ipc";return 0;}
    return 1;
}
static int io(int fd,unsigned char *p,size_t n,int writing) {
    while(n) {
        ssize_t got;
        if(!ready(fd,writing?POLLOUT:POLLIN))return 0;
        got=writing?write(fd,p,n):read(fd,p,n);
        if(got<0&&errno==EINTR)continue;
        if(got<=0){reason="malformed_ipc";return 0;}
        p+=got;n-=(size_t)got;
    }
    return 1;
}
static int emit(unsigned type,const void *data,size_t n) {
    unsigned char h[5]={(unsigned char)type,(unsigned char)(n>>24),(unsigned char)(n>>16),(unsigned char)(n>>8),(unsigned char)n};
    if(!io(1,h,5,1))return 0;
    return !n||io(1,(unsigned char *)data,n,1);
}
static int recv_frame(unsigned *type,size_t *n) {
    unsigned char h[5];
    if(!io(0,h,5,0))return 0;
    *type=h[0];*n=((size_t)h[1]<<24)|((size_t)h[2]<<16)|((size_t)h[3]<<8)|h[4];
    if(*n>FRAME_MAX){reason="malformed_ipc";return 0;}
    if(*n&&!io(0,frame,*n,0))return 0;
    if(*type==5&&!*n){aborted=1;reason="aborted";return 0;}
    return 1;
}
static int closed(const unsigned char *data,size_t n) {
    struct {const char *input,*output;} values[]={
        {"eof","transport_eof"},{"timeout","transport_timeout"},{"budget","budget_exhausted"},
        {"connect_failed","transport_eof"},{"aborted","aborted"}};
    for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) if(strlen(values[i].input)==n&&!memcmp(data,values[i].input,n)) {
        reason=values[i].output;connected=0;return 1;
    }
    reason="malformed_ipc";return 0;
}
static int connect_parent(void) {
    unsigned t;size_t n;
    if(connected||aborted){reason="malformed_ipc";return 0;}
    if(connections>=opt.max_connections){reason="budget_exhausted";return 0;}
    connections++;
    if(!emit(1,NULL,0)||!recv_frame(&t,&n))return 0;
    if(t==1&&!n){connected=1;return 1;}
    if(t==4){closed(frame,n);return 0;}
    reason="malformed_ipc";return 0;
}
static int drain(BIO *wire) {
    unsigned char out[FRAME_MAX];int n;
    while(BIO_ctrl_pending(wire)) {
        n=BIO_read(wire,out,sizeof(out));
        if(n<=0){reason="engine_error";return 0;}
        if((unsigned)n>BYTE_MAX-sent){reason="budget_exhausted";return 0;}
        sent+=(unsigned)n;
        if(!emit(2,out,(size_t)n))return 0;
    }
    return 1;
}
static int receive(BIO *wire) {
    unsigned t;size_t n;
    if(!recv_frame(&t,&n))return 0;
    if(t==4){closed(frame,n);return 0;}
    if(t!=2||!n||!connected){reason="malformed_ipc";return 0;}
    if(n>BYTE_MAX-received){reason="budget_exhausted";return 0;}
    received+=(unsigned)n;
    if(BIO_write(wire,frame,(int)n)!=(int)n){reason="malformed_ipc";return 0;}
    return 1;
}
static int close_parent(void) {
    unsigned t;size_t n;
    if(!connected)return 1;
    if(aborted)return 0;
    if(!emit(4,NULL,0))return 0;
    while(recv_frame(&t,&n)) {
        if(t==4)return closed(frame,n);
        if(t!=2||!n||n>BYTE_MAX-received){reason="malformed_ipc";return 0;}
        received+=(unsigned)n;
    }
    return 0;
}
static void info(const SSL *s,int where,int ret) {
    (void)s;
    if((where&SSL_CB_ALERT)&&(where&SSL_CB_READ)&&((ret>>8)==SSL3_AL_FATAL))peer_alert=ret&255;
}
static int save_session(SSL *s,SSL_SESSION *session) {
    (void)s;
    if(new_session)SSL_SESSION_free(new_session);
#if CM_LEGACY
    CRYPTO_add(&session->references,1,CRYPTO_LOCK_SSL_SESSION);
#else
    SSL_SESSION_up_ref(session);
#endif
    new_session=session;return 0;
}
static int do_handshake(SSL *ssl,BIO *wire) {
    for(;;) {
        int result,error;
        if(now_ms()>=deadline){reason="transport_timeout";return 0;}
        ERR_clear_error();result=SSL_do_handshake(ssl);error=SSL_get_error(ssl,result);
        if(!drain(wire))return 0;
        if(result==1)return 1;
        if(error==SSL_ERROR_WANT_WRITE)continue;
        if(error==SSL_ERROR_WANT_READ){if(!receive(wire))return 0;continue;}
        reason=peer_alert?"peer_alert":"handshake_failed";return 0;
    }
}
static int start_tls(SSL_CTX *ctx,SSL_SESSION *session,SSL **out,BIO **wire) {
    BIO *inside=NULL;SSL *s=SSL_new(ctx);
    if(!s||!BIO_new_bio_pair(&inside,FRAME_MAX,wire,FRAME_MAX)){SSL_free(s);reason="engine_error";return 0;}
    SSL_set_bio(s,inside,inside);SSL_set_connect_state(s);SSL_set_info_callback(s,info);
    if(opt.hostname&&strcmp(opt.protocol,"ssl2"))SSL_set_tlsext_host_name(s,opt.hostname);
    if(strcmp(opt.protocol,"ssl2"))SSL_set_tlsext_status_type(s,TLSEXT_STATUSTYPE_ocsp);
    if(strcmp(opt.alpn,"none")&&strcmp(opt.protocol,"ssl2")) {
        const unsigned char http1[]={8,'h','t','t','p','/','1','.','1'};
        const unsigned char both[]={2,'h','2',8,'h','t','t','p','/','1','.','1'};
        SSL_set_alpn_protos(s,!strcmp(opt.alpn,"http1")?http1:both,!strcmp(opt.alpn,"http1")?sizeof(http1):sizeof(both));
    }
    if(!strcmp(opt.control,"fallback"))SSL_set_mode(s,SSL_MODE_SEND_FALLBACK_SCSV);
    if(session&&!SSL_set_session(s,session)){SSL_free(s);BIO_free(*wire);*wire=NULL;reason="engine_error";return 0;}
    peer_alert=0;*out=s;
    if(!connect_parent())return 0;
    return do_handshake(s,*wire);
}
static void receive_ticket(SSL *ssl,BIO *wire) {
#if !CM_LEGACY
    if(strcmp(opt.protocol,"tls1_3")||(new_session&&SSL_SESSION_is_resumable(new_session)))return;
    uint64_t original_deadline=deadline, ticket_deadline=now_ms()+1000;
    if(ticket_deadline<deadline)deadline=ticket_deadline;
    for(int attempt=0;attempt<4&&connected&&now_ms()<deadline;attempt++) {
        unsigned char byte;
        ERR_clear_error();
        int ret=SSL_read(ssl,&byte,1),error=SSL_get_error(ssl,ret);
        if(!drain(wire)||ret>0)break;
        if(error==SSL_ERROR_WANT_READ) {
            if(!receive(wire))break;
        } else if(error!=SSL_ERROR_WANT_WRITE)break;
        if(new_session&&SSL_SESSION_is_resumable(new_session))break;
    }
    deadline=original_deadline;
#else
    (void)ssl;(void)wire;
#endif
}
static void assess_resumption(SSL_CTX *ctx,SSL **ssl,BIO **wire) {
    receive_ticket(*ssl,*wire);
    if(!new_session
#if !CM_LEGACY
       ||(!strcmp(opt.protocol,"tls1_3")&&!SSL_SESSION_is_resumable(new_session))
#endif
    ){state="uncertain";reason="ticket_not_received";return;}
#if !CM_LEGACY
    if(!strcmp(opt.protocol,"tls1_3")) {
        observed_early_data_max=SSL_SESSION_get_max_early_data(new_session);
        observed_early_data=1;
    }
#endif
    ERR_clear_error();
    if(SSL_shutdown(*ssl)<0||!drain(*wire)){state="uncertain";reason="handshake_failed";return;}
    const char *previous_reason=reason;
    close_parent();reason=previous_reason;
    SSL_free(*ssl);BIO_free(*wire);*ssl=NULL;*wire=NULL;finished=0;
    if(start_tls(ctx,new_session,ssl,wire)) {
        finished=1;
        if(SSL_session_reused(*ssl)){state="accepted";reason="resumption_completed";}
        else {state="rejected";reason="resumption_declined";}
    } else {state="uncertain";if(peer_alert)reason="peer_alert";}
}
static void assess_renegotiation(SSL *ssl,BIO *wire) {
    long before=SSL_total_renegotiations(ssl);
    if(SSL_renegotiate(ssl)!=1){state="uncertain";reason="control_unavailable";limit("engine_capability_limit");return;}
    if(do_handshake(ssl,wire)&&SSL_total_renegotiations(ssl)>before) {
        reneg_completed=1;state="accepted";reason="renegotiation_completed";
    } else {state="uncertain";}
}
static const char *protocol_name(int version) {
    switch(version) {
#ifdef SSL2_VERSION
        case SSL2_VERSION:return "ssl2";
#endif
        case SSL3_VERSION:return "ssl3";case TLS1_VERSION:return "tls1";
        case TLS1_1_VERSION:return "tls1_1";case TLS1_2_VERSION:return "tls1_2";
#ifdef TLS1_3_VERSION
        case TLS1_3_VERSION:return "tls1_3";
#endif
        default:return NULL;
    }
}
static int cipher_compatible(const SSL_CIPHER *c);
static SSL_CTX *context(void) {
    SSL_CTX *ctx=NULL;
#if CM_LEGACY
    const SSL_METHOD *method=NULL;
    if(!strcmp(opt.protocol,"ssl2"))method=SSLv2_client_method();
    else if(!strcmp(opt.protocol,"ssl3"))method=SSLv3_client_method();
    else if(!strcmp(opt.protocol,"tls1"))method=TLSv1_client_method();
    else if(!strcmp(opt.protocol,"tls1_1"))method=TLSv1_1_client_method();
    else if(!strcmp(opt.protocol,"tls1_2"))method=TLSv1_2_client_method();
    if(method)ctx=SSL_CTX_new(method);
#else
    int version=!strcmp(opt.protocol,"tls1_3")?TLS1_3_VERSION:!strcmp(opt.protocol,"tls1_2")?TLS1_2_VERSION:0;
    if(version){ctx=SSL_CTX_new(TLS_client_method());if(ctx){SSL_CTX_set_min_proto_version(ctx,version);SSL_CTX_set_max_proto_version(ctx,version);}}
#endif
    if(!ctx){state="unexecutable";reason="protocol_unavailable";return NULL;}
    SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);
    SSL_CTX_set_options(ctx,SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_session_cache_mode(ctx,SSL_SESS_CACHE_CLIENT|SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(ctx,save_session);
    if(opt.group) {
        const char *groups[]={"P-256","P-384","P-521","X25519","X448","ffdhe2048","ffdhe3072","ffdhe4096",NULL};
        if(!in_list(opt.group,groups)||SSL_CTX_set1_curves_list(ctx,opt.group)!=1) {
            state="unexecutable";reason="group_unavailable";SSL_CTX_free(ctx);return NULL;
        }
    }
#if !CM_LEGACY
    if(!strcmp(opt.protocol,"tls1_3")) {
        if(!SSL_CTX_set_ciphersuites(ctx,opt.cipher?opt.cipher:"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256")) {
            state="unexecutable";reason="cipher_unavailable";SSL_CTX_free(ctx);return NULL;
        }
    } else
#endif
    if(!SSL_CTX_set_cipher_list(ctx,opt.cipher?opt.cipher:"ALL:eNULL:!PSK:!SRP")) {
        state="unexecutable";reason="cipher_unavailable";SSL_CTX_free(ctx);return NULL;
    }
    if(opt.cipher&&(strstr(opt.cipher,"PSK")||strstr(opt.cipher,"SRP"))) {
        state="unexecutable";reason="requires_credentials";SSL_CTX_free(ctx);limit("credential_suites_unexecutable");return NULL;
    }
    if(opt.cipher) {
        SSL *probe=SSL_new(ctx);int exact=0;
        STACK_OF(SSL_CIPHER) *list=probe?SSL_get_ciphers(probe):NULL;
        for(int i=0;list&&i<sk_SSL_CIPHER_num(list);i++) {
            const SSL_CIPHER *c=sk_SSL_CIPHER_value(list,i);
            if(!strcmp(SSL_CIPHER_get_name(c),opt.cipher)&&cipher_compatible(c))exact=1;
        }
        SSL_free(probe);
        if(!exact){state="unexecutable";reason="cipher_unavailable";SSL_CTX_free(ctx);return NULL;}
    }
    return ctx;
}
static void hex(const unsigned char *in,size_t n,char *out) {
    static const char digits[]="0123456789abcdef";
    for(size_t i=0;i<n;i++){out[i*2]=digits[in[i]>>4];out[i*2+1]=digits[in[i]&15];}out[n*2]=0;
}
static void load_trust(void) {
    unsigned char bytes[8192],digest[32];SHA256_CTX hash;size_t n;unsigned total=0;
    if(!opt.trust){limit("no_trust_snapshot");return;}
    FILE *f=fopen(opt.trust,"rb");
    if(!f){limit("no_trust_snapshot");return;}
    SHA256_Init(&hash);
    while((n=fread(bytes,1,sizeof(bytes),f))) {
        if(n>8388608-total){fclose(f);limit("no_trust_snapshot");return;}
        total+=(unsigned)n;SHA256_Update(&hash,bytes,n);
    }
    int bad=ferror(f);fclose(f);
    if(bad){limit("no_trust_snapshot");return;}
    SHA256_Final(digest,&hash);hex(digest,32,trust_hash);
    trust_store=X509_STORE_new();
    if(trust_store&&X509_STORE_load_locations(trust_store,opt.trust,NULL)==1)trust_loaded=1;
    else {trust_hash[0]=0;limit("no_trust_snapshot");}
}
static int leap_year(int year) {
    return year%4==0&&(year%100!=0||year%400==0);
}
static int64_t days_from_civil(int year,int month,int day) {
    year-=month<=2;
    int era=(year>=0?year:year-399)/400;
    unsigned year_of_era=(unsigned)(year-era*400);
    unsigned day_of_year=(153U*(unsigned)(month+(month>2?-3:9))+2)/5+(unsigned)day-1;
    unsigned year_day=year_of_era*365+year_of_era/4-year_of_era/100+day_of_year;
    return (int64_t)era*146097+year_day-719468;
}
/* ASN.1 UTC and generalized time parsing; no locale or timezone dependency. */
static int asn1_epoch(const ASN1_TIME *value,int64_t *epoch) {
    const unsigned char *s;int n,year=0,pos=0;
    if(!value)return 0;
    s=ASN1_STRING_data((ASN1_STRING *)value);
    n=ASN1_STRING_length(value);
    int generalized=ASN1_STRING_type((ASN1_STRING *)value)==V_ASN1_GENERALIZEDTIME;
    if(n!=(generalized?15:13)||s[n-1]!='Z')return 0;
    for(int i=0;i<n-1;i++)if(!isdigit(s[i]))return 0;
    if(generalized){year=(s[0]-'0')*1000+(s[1]-'0')*100;pos=2;}
    year+=(s[pos]-'0')*10+s[pos+1]-'0';pos+=2;
    if(!generalized)year+=year<50?2000:1900;
    int month=(s[pos]-'0')*10+s[pos+1]-'0';pos+=2;
    int day=(s[pos]-'0')*10+s[pos+1]-'0';pos+=2;
    int hour=(s[pos]-'0')*10+s[pos+1]-'0';pos+=2;
    int minute=(s[pos]-'0')*10+s[pos+1]-'0';pos+=2;
    int second=(s[pos]-'0')*10+s[pos+1]-'0';
    static const int month_days[]={0,31,28,31,30,31,30,31,31,30,31,30,31};
    if(year<1||year>9999||month<1||month>12||day<1||day>month_days[month]+(month==2&&leap_year(year))
       ||hour>23||minute>59||second>59)return 0;
    *epoch=days_from_civil(year,month,day)*86400+hour*3600+minute*60+second;
    return 1;
}
static void time_json(const ASN1_TIME *t) {int64_t v;if(asn1_epoch(t,&v))append("%lld",(long long)v);else append("null");}
static void digest_cert(X509 *cert,char output[65]) {
    unsigned char digest[32];unsigned n=0;
    if(!X509_digest(cert,EVP_sha256(),digest,&n)||n!=32)_exit(4);
    hex(digest,32,output);
}
static const char *key_type(EVP_PKEY *key) {
    if(!key)return "UNKNOWN";
    switch(EVP_PKEY_base_id(key)) {
        case EVP_PKEY_RSA:return "RSA";case EVP_PKEY_EC:return "EC";case EVP_PKEY_DSA:return "DSA";case EVP_PKEY_DH:return "DH";
#ifdef EVP_PKEY_ED25519
        case EVP_PKEY_ED25519:return "ED25519";case EVP_PKEY_ED448:return "ED448";
#endif
        default:return "UNKNOWN";
    }
}
static const char *signature(int nid) {
    switch(nid) {
        case NID_md5WithRSAEncryption:return "rsa_md5";case NID_sha1WithRSAEncryption:return "rsa_sha1";
        case NID_sha256WithRSAEncryption:return "rsa_sha256";case NID_sha384WithRSAEncryption:return "rsa_sha384";
        case NID_sha512WithRSAEncryption:return "rsa_sha512";case NID_rsassaPss:return "rsa_pss";
        case NID_ecdsa_with_SHA1:return "ecdsa_sha1";case NID_ecdsa_with_SHA256:return "ecdsa_sha256";
        case NID_ecdsa_with_SHA384:return "ecdsa_sha384";case NID_ecdsa_with_SHA512:return "ecdsa_sha512";
        case NID_dsaWithSHA1:return "dsa_sha1";case NID_dsa_with_SHA256:return "dsa_sha256";
#ifdef NID_ED25519
        case NID_ED25519:return "ed25519";case NID_ED448:return "ed448";
#endif
        default:return "unknown";
    }
}
static void certificate_json(X509 *x) {
    char digest[65],spki[65];unsigned char bytes[32],*der=NULL;EVP_PKEY *key=X509_get_pubkey(x);
    int n=i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x),&der);
    digest_cert(x,digest);
    if(n<=0||!der)_exit(4);
    SHA256(der,(size_t)n,bytes);
    OPENSSL_free(der);
    hex(bytes,32,spki);
    int bits=key?EVP_PKEY_bits(key):0;if(bits<0||bits>16384)bits=0;
    int self=X509_NAME_cmp(X509_get_subject_name(x),X509_get_issuer_name(x))==0&&key&&X509_verify(x,key)==1;
    append("{\"sha256\":\"%s\",\"spki_sha256\":\"%s\",\"not_before\":",digest,spki);time_json(X509_get_notBefore(x));
    append(",\"not_after\":");time_json(X509_get_notAfter(x));
    append(",\"key_type\":\"%s\",\"key_bits\":%d,\"signature_algorithm\":\"%s\",\"self_signed\":%s,\"ca\":%s}",key_type(key),bits,signature(X509_get_signature_nid(x)),boolean(self),boolean(X509_check_ca(x)>0));
    EVP_PKEY_free(key);
}
static const char *trust_reason(int error) {
    switch(error) {
        case X509_V_OK:return "trusted";
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:return "issuer_missing";
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:return "self_signed";
        case X509_V_ERR_CERT_HAS_EXPIRED:return "expired";case X509_V_ERR_CERT_NOT_YET_VALID:return "not_yet_valid";
        case X509_V_ERR_CERT_SIGNATURE_FAILURE:return "signature_invalid";case X509_V_ERR_INVALID_PURPOSE:return "invalid_purpose";
        default:return "trust_unknown";
    }
}
static STACK_OF(X509) *certificates_json(SSL *s,X509 **leaf_out) {
    X509 *leaf=SSL_get_peer_certificate(s);STACK_OF(X509) *offered=SSL_get_peer_cert_chain(s),*built=NULL;
    *leaf_out=leaf;
    if(!leaf){append("null");return NULL;}
    int n=offered?sk_X509_num(offered):0;int single=n==0,overflow=n>CHAIN_MAX;
    if(single){n=1;if(!strcmp(opt.protocol,"ssl2"))limit("ssl2_single_certificate");}
    if(overflow)limit("certificate_chain_limit");
    int valid=-1,error=X509_V_ERR_UNSPECIFIED;
    if(trust_loaded&&!overflow) {
        X509_STORE_CTX *verify=X509_STORE_CTX_new();
        if(verify&&X509_STORE_CTX_init(verify,trust_store,leaf,offered)==1) {
            X509_STORE_CTX_set_purpose(verify,X509_PURPOSE_SSL_SERVER);
            X509_STORE_CTX_set_time(verify,0,evaluated);
            valid=X509_verify_cert(verify);error=X509_STORE_CTX_get_error(verify);
            if(valid==1)built=X509_STORE_CTX_get1_chain(verify);
        }
        X509_STORE_CTX_free(verify);
    }
    if(built&&sk_X509_num(built)>CHAIN_MAX){sk_X509_pop_free(built,X509_free);built=NULL;valid=-1;overflow=1;limit("certificate_chain_limit");}
    append("{\"offered_chain\":[");
    for(int i=0;i<n&&i<CHAIN_MAX;i++){if(i)append(",");certificate_json(single?leaf:sk_X509_value(offered,i));}
    append("],\"trusted_chain\":[");
    if(built)for(int i=0;i<sk_X509_num(built);i++){char digest[65];digest_cert(sk_X509_value(built,i),digest);append("%s\"%s\"",i?",":"",digest);}
    int dates=X509_cmp_time(X509_get_notBefore(leaf),&evaluated)<=0&&X509_cmp_time(X509_get_notAfter(leaf),&evaluated)>0;
    append("],\"trust\":\"%s\",\"hostname\":%s,\"dates\":%s,\"reason\":\"%s\",\"evaluation_at\":%lld,\"trust_bundle_sha256\":",valid==1?"valid":valid==0?"invalid":"unknown",boolean(opt.hostname?X509_check_host(leaf,opt.hostname,0,X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,NULL)==1:-1),boolean(dates),overflow?"chain_limit":valid<0?"trust_unknown":trust_reason(error),(long long)evaluated);
    if(trust_hash[0])append("\"%s\"}",trust_hash);else append("null}");
    return built;
}
static void ocsp_json(SSL *s,X509 *leaf,STACK_OF(X509) *built) {
    const unsigned char *der=NULL;long length=SSL_get_tlsext_status_ocsp_resp(s,&der);
    int sig=-1,match=-1,fresh=-1;const char *status="absent";ASN1_GENERALIZEDTIME *this_update=NULL,*next_update=NULL;
    OCSP_RESPONSE *response=NULL;OCSP_BASICRESP *basic=NULL;
    if(length<=0){limit("no_stapled_ocsp");goto done;}
    status="invalid";
    if(length>65536||!der||!leaf)goto done;
    const unsigned char *cursor=der;
    response=d2i_OCSP_RESPONSE(NULL,&cursor,length);
    if(!response||cursor!=der+length||OCSP_response_status(response)!=OCSP_RESPONSE_STATUS_SUCCESSFUL)goto done;
    basic=OCSP_response_get1_basic(response);if(!basic)goto done;
    STACK_OF(X509) *offered=SSL_get_peer_cert_chain(s);
    if(trust_loaded)sig=OCSP_basic_verify(basic,offered,trust_store,0)==1;
    X509 *issuer=NULL;
    if(built&&sk_X509_num(built)>1)issuer=sk_X509_value(built,1);
    if(!issuer&&offered)for(int i=0;i<sk_X509_num(offered);i++)if(X509_check_issued(sk_X509_value(offered,i),leaf)==X509_V_OK){issuer=sk_X509_value(offered,i);break;}
    if(!issuer&&X509_check_issued(leaf,leaf)==X509_V_OK)issuer=leaf;
    if(!issuer)goto done;
    match=0;
    for(int i=0;i<OCSP_resp_count(basic)&&i<32;i++) {
        OCSP_SINGLERESP *single=OCSP_resp_get0(basic,i);
#if CM_LEGACY
        OCSP_CERTID *id=single->certId;
#else
        OCSP_CERTID *id=(OCSP_CERTID *)OCSP_SINGLERESP_get0_id(single);
#endif
        ASN1_OBJECT *algorithm=NULL;OCSP_id_get0_info(NULL,&algorithm,NULL,NULL,id);
        const EVP_MD *md=EVP_get_digestbyobj(algorithm);if(!md)continue;
        OCSP_CERTID *expected=OCSP_cert_to_id(md,leaf,issuer);
        int equals=expected&&OCSP_id_cmp(expected,id)==0;OCSP_CERTID_free(expected);
        if(!equals)continue;
        int why;ASN1_GENERALIZEDTIME *revocation;
        int cert_status=OCSP_single_get0_status(single,&why,&revocation,&this_update,&next_update);
        match=1;fresh=OCSP_check_validity(this_update,next_update,300,86400)==1;
        if(sig==1&&fresh==1)status=cert_status==V_OCSP_CERTSTATUS_GOOD?"good":cert_status==V_OCSP_CERTSTATUS_REVOKED?"revoked":"unknown";
        break;
    }
 done:
    append("{\"state\":\"%s\",\"signature_valid\":%s,\"cert_id_match\":%s,\"fresh\":%s,\"this_update\":",status,boolean(sig),boolean(match),boolean(fresh));time_json((ASN1_TIME *)this_update);
    append(",\"next_update\":");time_json((ASN1_TIME *)next_update);append("}");
    OCSP_BASICRESP_free(basic);OCSP_RESPONSE_free(response);
}
static void negotiated_json(SSL *s) {
    const SSL_CIPHER *cipher=SSL_get_current_cipher(s);const char *version=protocol_name(SSL_version(s));
    const char *name=cipher?SSL_CIPHER_get_name(cipher):NULL;
    if(!name||!version||!identifier(name,96)){append("null");return;}
    EVP_PKEY *key=NULL;int bits=0,pfs=-1;const char *group=NULL;
    if(SSL_get_server_tmp_key(s,&key)==1&&key) {
        bits=EVP_PKEY_bits(key);pfs=EVP_PKEY_base_id(key)==EVP_PKEY_DH||EVP_PKEY_base_id(key)==EVP_PKEY_EC;
#if !CM_LEGACY
        if(EVP_PKEY_base_id(key)==EVP_PKEY_X25519||EVP_PKEY_base_id(key)==EVP_PKEY_X448)pfs=1;
#endif
        if(EVP_PKEY_base_id(key)==EVP_PKEY_EC) {
            EC_KEY *ec=EVP_PKEY_get1_EC_KEY(key);
            if(ec){group=OBJ_nid2sn(EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)));EC_KEY_free(ec);}
        }
        else if(EVP_PKEY_base_id(key)==EVP_PKEY_DH)group="DH";
#if !CM_LEGACY
        else if(EVP_PKEY_base_id(key)==EVP_PKEY_X25519)group="X25519";
        else if(EVP_PKEY_base_id(key)==EVP_PKEY_X448)group="X448";
#endif
    }
    /* Only a verified static-RSA key exchange proves absent forward secrecy.
     * The legacy bit comes from pinned 1.0.2u ssl_locl.h (SSL_kRSA=0x1). */
    if(pfs<0) {
#if CM_LEGACY
        if(cipher->algorithm_mkey&0x00000001UL)pfs=0;
#else
        if(SSL_CIPHER_get_kx_nid(cipher)==NID_kx_rsa)pfs=0;
#endif
    }
    append("{\"version\":\"%s\",\"cipher\":\"%s\",\"cipher_bits\":%d,\"group\":",version,name,SSL_CIPHER_get_bits(cipher,NULL));
    if(group&&identifier(group,64))append("\"%s\"",group);else append("null");
    append(",\"group_bits\":");if(bits>0&&bits<=16384)append("%d",bits);else append("null");
    const unsigned char *alpn=NULL;unsigned alpn_len=0;SSL_get0_alpn_selected(s,&alpn,&alpn_len);
    append(",\"pfs\":%s,\"alpn\":",boolean(pfs));
    if(alpn_len==2&&!memcmp(alpn,"h2",2))append("\"h2\"");else if(alpn_len==8&&!memcmp(alpn,"http/1.1",8))append("\"http/1.1\"");else append("null");
    append(",\"sni_sent\":%s}",boolean(opt.hostname&&strcmp(opt.protocol,"ssl2")));EVP_PKEY_free(key);
}
static void extensions_json(SSL *s) {
    int ems=-1;uint32_t early=0;
#if CM_LEGACY
    /* This release does not offer EMS. Null is not server rejection. */
#else
    if(strcmp(opt.protocol,"tls1_3"))ems=SSL_get_extms_support(s);
    if(new_session)early=SSL_SESSION_get_max_early_data(new_session);
#endif
    /* This build never offers compression; absence in a handshake is unknown. */
    append("{\"ems\":%s,\"compression\":%s,\"secure_renegotiation\":%s,\"fallback_scsv\":%s,\"session_reused\":%s,\"early_data_max\":",boolean(ems),boolean(SSL_get_current_compression(s)!=NULL?1:-1),boolean(!strcmp(opt.protocol,"ssl2")?-1:(int)SSL_get_secure_renegotiation_support(s)),boolean(!strcmp(opt.control,"fallback")?peer_alert==86:-1),boolean(SSL_session_reused(s)));
    if(!strcmp(opt.protocol,"tls1_3")&&observed_early_data)append("%u",observed_early_data_max);
    else if(!strcmp(opt.protocol,"tls1_3")&&new_session)append("%u",early);
    else append("null");
    append(",\"renegotiation_completed\":%s}",boolean(reneg_completed));
}
static int cipher_compatible(const SSL_CIPHER *c) {
    const char *version=SSL_CIPHER_get_version(c);
    if(!strcmp(opt.protocol,"ssl2"))return !strcmp(version,"SSLv2");
    if(!strcmp(opt.protocol,"tls1_3"))return !strcmp(version,"TLSv1.3");
    if(!strcmp(version,"TLSv1.3")||!strcmp(version,"SSLv2"))return 0;
#if CM_LEGACY
    /* Pinned 1.0.2u ssl_locl.h SSL_TLSV1_2 = 0x4. Its public version
     * getter collapses every 0x03-prefixed suite to TLSv1/SSLv3. */
    if(strcmp(opt.protocol,"tls1_2")&&(c->algorithm_ssl&0x4UL))return 0;
#else
    if(strcmp(opt.protocol,"tls1_2")&&!strcmp(version,"TLSv1.2"))return 0;
#endif
    return 1;
}
static void catalog_json(SSL_CTX *ctx) {
    SSL *s=ctx?SSL_new(ctx):NULL;int count=0;
    append("[");
    if(s) {
        /* Include credential suites, with their honest unexecutable reason. */
        SSL_set_cipher_list(s,"ALL:eNULL");STACK_OF(SSL_CIPHER) *list=SSL_get_ciphers(s);
        for(int i=0;i<sk_SSL_CIPHER_num(list)&&count<500;i++) {
            const SSL_CIPHER *c=sk_SSL_CIPHER_value(list,i);const char *name=SSL_CIPHER_get_name(c);
            if(!cipher_compatible(c)||!identifier(name,96))continue;
            int credentials=strstr(name,"PSK")!=NULL||strstr(name,"SRP")!=NULL;
            append("%s{\"name\":\"%s\",\"id\":\"%0*lx\",\"bits\":%d,\"executable\":%s,\"reason\":\"%s\"}",count?",":"",name,!strcmp(opt.protocol,"ssl2")?6:4,SSL_CIPHER_get_id(c)&(!strcmp(opt.protocol,"ssl2")?0xffffffUL:0xffffUL),SSL_CIPHER_get_bits(c,NULL),boolean(!credentials),credentials?"requires_credentials":"executable");count++;
        }
    }
    append("]");SSL_free(s);
}
static void result(SSL_CTX *ctx,SSL *ssl) {
    uint64_t duration=now_ms()-started;X509 *leaf=NULL;STACK_OF(X509) *built=NULL;
    json_len=0;
    append("{\"schema\":\"tls-engine-result-v1\",\"engine\":{\"family\":\"%s\",\"version\":\"%s\",\"build_id\":\"%s\",\"sandboxed\":%s},\"control\":\"%s\",\"protocol\":\"%s\",\"state\":\"%s\",\"reason\":\"%s\",\"authenticated_finished\":%s,\"vulnerability\":null,\"negotiated\":",CM_ENGINE_FAMILY,CM_LEGACY?"1.0.2u":"3.5.9",CM_BUILD_ID,boolean(sandboxed),opt.control,opt.protocol,state,reason,boolean(finished));
    if(finished&&ssl)negotiated_json(ssl);else append("null");
    append(",\"certificates\":");if(finished&&ssl)built=certificates_json(ssl,&leaf);else append("null");
    append(",\"ocsp\":");if(finished&&ssl)ocsp_json(ssl,leaf,built);else append("null");
    append(",\"extensions\":");if(finished&&ssl)extensions_json(ssl);else append("null");
    append(",\"telemetry\":{\"connections\":%u,\"bytes_sent\":%u,\"bytes_received\":%u,\"duration_ms\":%llu},\"limitations\":[",connections,sent,received,(unsigned long long)(duration>30000?30000:duration));
    for(unsigned i=0;i<limitation_count;i++)append("%s\"%s\"",i?",":"",limitations[i]);
    append("],\"catalog\":");if(!strcmp(opt.control,"catalog"))catalog_json(ctx);else append("null");append("}");
    X509_free(leaf);sk_X509_pop_free(built,X509_free);
    /* A final result gets a short pipe-delivery grace. No network work follows. */
    deadline=now_ms()+1000;emit(3,json,json_len);
}
int main(int argc,char **argv) {
    if(!args(argc,argv))return 2;
    started=now_ms();deadline=started+opt.timeout;evaluated=time(NULL);signal(SIGPIPE,SIG_IGN);
#if CM_LEGACY
    SSL_library_init();OpenSSL_add_all_algorithms();
#else
    OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG,NULL);
#endif
    unsigned char seed[32];if(RAND_bytes(seed,sizeof(seed))!=1)return 3;OPENSSL_cleanse(seed,sizeof(seed));
    load_trust();SSL_CTX *ctx=context();SSL *ssl=NULL;BIO *wire=NULL;
    sandboxed=cm_sandbox();
#if defined(__linux__)
    if(!sandboxed)return 3;
#else
    if(!sandboxed)limit("os_sandbox_unavailable");
#endif
    if(!strcmp(opt.protocol,"ssl2")){limit("ssl2_export_unavailable");limit("ssl2_single_des_unavailable");}
    if(!ctx)goto done;
    if(!strcmp(opt.control,"catalog")){state="accepted";reason="catalog_ready";goto done;}
    if(!strcmp(opt.control,"compression")){state="unexecutable";reason="control_unavailable";limit("compression_not_offered");goto done;}
    if(!strcmp(opt.control,"heartbleed")||!strcmp(opt.control,"robot")||!strcmp(opt.control,"ccs")) {
        state="unexecutable";reason="control_unavailable";limit("engine_capability_limit");goto done;
    }
    if(!strcmp(opt.control,"renegotiation")&&!strcmp(opt.protocol,"tls1_3")) {state="not_applicable";reason="protocol_not_applicable";goto done;}
    if(start_tls(ctx,NULL,&ssl,&wire)) {
        finished=1;state="accepted";reason="handshake_completed";
        if(!strcmp(opt.control,"renegotiation"))assess_renegotiation(ssl,wire);
        else if(!strcmp(opt.control,"resumption"))assess_resumption(ctx,&ssl,&wire);
    } else if(peer_alert){
        if(peer_alert==86&&!strcmp(opt.control,"fallback")){state="rejected";reason="fallback_rejected";}
        else if(peer_alert==70&&(!strcmp(opt.control,"handshake")||!strcmp(opt.control,"certificate"))){
            state="rejected";reason="protocol_version_rejected";
        } else {state="uncertain";reason="peer_alert";}
    }
    if(connected){const char *saved=reason;close_parent();reason=saved;}
 done:
    result(ctx,ssl);SSL_free(ssl);BIO_free(wire);SSL_CTX_free(ctx);SSL_SESSION_free(new_session);X509_STORE_free(trust_store);
    return 0;
}
