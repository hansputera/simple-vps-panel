/* panel.c: VPS panel in C, sites manager, dashboard (cpu/uptime/fail2ban),
 * RCE terminal, process manager, systemd services manager.
 * build: gcc -O2 -Wall -o panel panel.c -lmicrohttpd -lcrypt -lpthread */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <microhttpd.h>
#include <crypt.h>
#include <malloc.h>
#include <poll.h>
/* glibc: aggressive heap trim; musl: mallocng trims automatically */
#ifdef __GLIBC__
#define trim_heap() malloc_trim(0)
#else
#define trim_heap() ((void)0)
#endif
#include <ftw.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#ifndef PORT
#define PORT        8088
#endif
#ifndef BASE
#define BASE        "/opt/caddy-panel-c"
#endif
#define HTML_PATH   BASE "/index.html"
#define CONFIG_PATH BASE "/config"
#define SITES_PATH  BASE "/sites.conf"
#define EXTRADIR    BASE "/extra"
#define SITES_DIR   "/etc/caddy/sites"
#define CADDYFILE   "/etc/caddy/Caddyfile"
#ifndef CREDS_PATH
#define CREDS_PATH "/root/panel-credentials.txt"
#endif
#define MAX_OUTPUT  (256*1024)
#define EXEC_TIMEOUT 60

/* ---------- dynamic string ---------- */
typedef struct { char *s; size_t len, cap; } SB;
static void sb_init(SB *b){ b->cap=1024; b->len=0; b->s=malloc(b->cap); b->s[0]=0; }
static void sb_free(SB *b){ free(b->s); b->s=NULL; }
static void sb_putn(SB *b, const char *s, size_t n){
    if(b->len+n+1>b->cap){ while(b->len+n+1>b->cap) b->cap*=2; b->s=realloc(b->s,b->cap); }
    memcpy(b->s+b->len,s,n); b->len+=n; b->s[b->len]=0;
}
static void sb_put(SB *b, const char *s){ sb_putn(b,s,strlen(s)); }
static void sb_putc(SB *b, char c){ sb_putn(b,&c,1); }
static void sb_fmt(SB *b, const char *fmt, ...){
    char tmp[4096]; va_list ap; va_start(ap,fmt);
    vsnprintf(tmp,sizeof(tmp),fmt,ap); va_end(ap); sb_put(b,tmp);
}
static void sb_json(SB *b, const char *s){
    sb_putc(b,'"');
    for(const unsigned char *p=(const unsigned char*)s; *p; p++){
        unsigned char c=*p;
        switch(c){
        case '"': sb_put(b,"\\\""); break;
        case '\\': sb_put(b,"\\\\"); break;
        case '\n': sb_put(b,"\\n"); break;
        case '\r': sb_put(b,"\\r"); break;
        case '\t': sb_put(b,"\\t"); break;
        default:
            if(c<0x20) sb_fmt(b,"\\u%04x",c);
            else sb_putc(b,c);
        }
    }
    sb_putc(b,'"');
}

/* ---------- subprocess capture ---------- */
static int run_capture(char *const argv[], char **out, size_t cap, int timeout, int *ec){
    int fds[2]; if(pipe(fds)){ *out=strdup(""); return -1; }
    pid_t pid=fork();
    if(pid<0){ close(fds[0]); close(fds[1]); *out=strdup(""); return -1; }
    if(pid==0){
        setpgid(0,0);
        close(fds[0]);
        dup2(fds[1],1); dup2(fds[1],2); close(fds[1]);
        execvp(argv[0],argv); _exit(127);
    }
    close(fds[1]);
    SB sb; sb_init(&sb);
    time_t deadline=time(NULL)+timeout;
    struct pollfd pfd={.fd=fds[0],.events=POLLIN};
    int timedout=0, rc, child_gone=0, st=0;
    while(1){
        int remain=(int)(deadline-time(NULL)); if(remain<0) remain=0;
        if(remain==0){ timedout=1; break; }
        rc=poll(&pfd,1,250);
        if(rc>0){
            char chunk[8192]; ssize_t n=read(fds[0],chunk,sizeof(chunk));
            if(n==0) break;
            if(n>0 && (size_t)sb.len<cap) sb_putn(&sb,chunk,(size_t)n<(cap-sb.len)?(size_t)n:cap-sb.len);
        }
        if(!child_gone){
            int wr=waitpid(pid,&st,WNOHANG);
            if(wr==pid){
                child_gone=1;
                /* drain whatever is buffered, then stop (grandchildren may hold pipe) */
                int fl=fcntl(fds[0],F_GETFL); fcntl(fds[0],F_SETFL,fl|O_NONBLOCK);
                char chunk[8192]; ssize_t n;
                while((n=read(fds[0],chunk,sizeof(chunk)))>0){
                    if((size_t)sb.len<cap) sb_putn(&sb,chunk,(size_t)n<(cap-sb.len)?(size_t)n:cap-sb.len);
                }
                break;
            }
        }
    }
    close(fds[0]);
    if(timedout){ kill(-pid,SIGKILL); kill(pid,SIGKILL); waitpid(pid,&st,0); }
    else if(!child_gone){ waitpid(pid,&st,0); }
    waitpid(pid,&st,0);
    if(ec) *ec = timedout?124 : (WIFEXITED(st)?WEXITSTATUS(st):128+WTERMSIG(st));
    *out=sb.s;
    return 0;
}

/* ---------- config / auth ---------- */
static char g_hash[256];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct { char token[65]; time_t exp; } Session;
#define MAX_SESS 64
static Session g_sessions[MAX_SESS];
/* per-IP failed-login tracker: 5 fails in 5 min -> that IP waits */
typedef struct { char ip[64]; time_t t[8]; int n; } IPRec;
#define MAX_IPS 64
static IPRec g_ips[MAX_IPS]; static int g_nips=0;

static const char *B64="./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static void rnd_str(char *dst, int n, const char *alpha){
    static int seeded; if(!seeded){ srandom(getpid()^time(NULL)^random()); seeded=1; }
    int al=strlen(alpha);
    for(int i=0;i<n;i++){ dst[i]=alpha[random()%al]; }
    dst[n]=0;
}
static void load_or_init_config(void){
    FILE *f=fopen(CONFIG_PATH,"r");
    if(f){
        char line[512];
        while(fgets(line,sizeof(line),f))
            if(!strncmp(line,"hash=",5)){ line[strcspn(line,"\n")]=0; snprintf(g_hash,sizeof(g_hash),"%s",line+5); }
        fclose(f);
    }
    if(!g_hash[0]){
        char pw[17], salt[40], rnd[23];
        rnd_str(pw,16,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
        rnd_str(rnd,22,B64);
        snprintf(salt,sizeof(salt),"$2b$10$%s",rnd);
        struct crypt_data d={.initialized=0};
        char *h=crypt_r(pw,salt,&d);
        f=fopen(CONFIG_PATH,"w"); fprintf(f,"hash=%s\n",h); fclose(f);
        chmod(CONFIG_PATH,0600);
        f=fopen(CREDS_PATH,"w");
        fprintf(f,"Panel: https://tencent140.vps.hanifu.id\nPassword: %s\n(CHANGE after first login)\n",pw);
        fclose(f); chmod(CREDS_PATH,0600);
        snprintf(g_hash,sizeof(g_hash),"%s",h);
        printf("initial credentials written to %s\n",CREDS_PATH);
    }
}
static int check_pw(const char *pw){
    struct crypt_data d={.initialized=0};
    char *r=crypt_r(pw,g_hash,&d);
    return r && !strcmp(r,g_hash);
}

/* ---------- sites ---------- */
typedef struct { char domain[256]; char target[256]; char auth_user[128]; char auth_hash[128]; char extra[4096]; } Site;
static Site g_sites[64]; static int g_nsites=0;

static int valid_domain(const char *d){
    size_t n=strlen(d); if(!n||n>253) return 0;
    const char *p=d; int lab=0;
    while(*p){
        if(*p=='.'){ if(!lab||lab>63) return 0; lab=0; p++; continue; }
        if(!(islower((unsigned char)*p)||isdigit((unsigned char)*p)||*p=='-')) return 0;
        if((*p=='-')&&(p==d||lab==0)) return 0;
        lab++; p++;
        if(lab==1&&isdigit((unsigned char)d[0])&&n==strspn(d,"0123456789.")) { /* ok ip-ish not allowed for site */ }
    }
    return lab>0;
}
static int valid_target(const char *t){
    const char *c=strrchr(t,':'); if(!c||c==t) return 0;
    int port=atoi(c+1); if(port<1||port>65535) return 0;
    size_t hl=c-t; if(hl>253) return 0;
    for(size_t i=0;i<hl;i++){
        char ch=t[i];
        if(!(isalnum((unsigned char)ch)||ch=='.'||ch=='-'||ch=='_')) return 0;
    }
    return 1;
}
static int valid_user(const char *u){
    if(!*u) return 0;
    size_t n=strlen(u); if(n>64) return 0;
    for(size_t i=0;i<n;i++){ char c=u[i];
        if(!(isalnum((unsigned char)c)||c=='.'||c=='_'||c=='@'||c=='-')) return 0; }
    return 1;
}
static void load_sites(void){
    g_nsites=0;
    FILE *f=fopen(SITES_PATH,"r"); if(!f) return;
    char line[768];
    while(fgets(line,sizeof(line),f)&&g_nsites<64){
        line[strcspn(line,"\n")]=0;
        char *a=strtok(line,"|"), *b=strtok(NULL,"|"), *c=strtok(NULL,"|"), *d=strtok(NULL,"|");
        if(!a||!b) continue;
        Site *s=&g_sites[g_nsites++];
        snprintf(s->domain,sizeof(s->domain),"%s",a);
        snprintf(s->target,sizeof(s->target),"%s",b);
        snprintf(s->auth_user,sizeof(s->auth_user),"%s",c?c:"");
        snprintf(s->auth_hash,sizeof(s->auth_hash),"%s",d?d:"");
        s->extra[0]=0;
        char ep[512]; snprintf(ep,sizeof(ep),EXTRADIR "/%s.conf",s->domain);
        FILE *ef=fopen(ep,"r");
        if(ef){ size_t k=fread(s->extra,1,sizeof(s->extra)-1,ef); s->extra[k]=0; fclose(ef); }
    }
    fclose(f);
}
static void save_sites(void){
    FILE *f=fopen(SITES_PATH,"w");
    for(int i=0;i<g_nsites;i++)
        fprintf(f,"%s|%s|%s|%s\n",g_sites[i].domain,g_sites[i].target,g_sites[i].auth_user,g_sites[i].auth_hash);
    fclose(f);
    chmod(SITES_PATH,0600);
    mkdir(EXTRADIR,0755);
    /* write extra files, prune stale ones */
    char keep[64][256]; int nkeep=0;
    for(int i=0;i<g_nsites;i++){
        snprintf(keep[nkeep++],256,"%s.conf",g_sites[i].domain);
        if(g_sites[i].extra[0]){
            char ep[512]; snprintf(ep,sizeof(ep),EXTRADIR "/%s.conf",g_sites[i].domain);
            FILE *ef=fopen(ep,"w");
            if(ef){ fwrite(g_sites[i].extra,1,strlen(g_sites[i].extra),ef); fclose(ef); }
        }
    }
    DIR *d=opendir(EXTRADIR);
    if(d){ struct dirent *e;
        while((e=readdir(d))){
            size_t ln=strlen(e->d_name);
            if(ln<6||strcmp(e->d_name+ln-5,".conf")) continue;
            int found=0;
            for(int i=0;i<nkeep;i++) if(!strcmp(keep[i],e->d_name)) found=1;
            if(!found){ char ep[512]; snprintf(ep,sizeof(ep),EXTRADIR "/%s",e->d_name); unlink(ep); }
        } closedir(d);
    }
}
static void site_snippet(SB *b, Site *s){
    sb_fmt(b,"%s {\n\treverse_proxy %s\n\tencode zstd gzip\n\theader {\n\t\tStrict-Transport-Security \"max-age=31536000\"\n\t\tX-Content-Type-Options \"nosniff\"\n\t\t-Server\n\t}\n",s->domain,s->target);
    if(s->auth_user[0]) sb_fmt(b,"\tbasic_auth {\n\t\t%s %s\n\t}\n",s->auth_user,s->auth_hash);
    if(s->extra[0]){
        char *tmp=strdup(s->extra);
        char *line=strtok(tmp,"\n");
        while(line){ sb_putc(b,'\t'); sb_put(b,line); sb_putc(b,'\n'); line=strtok(NULL,"\n"); }
        free(tmp);
    }
    sb_put(b,"}\n");
}
static int caddy_run(char *const argv[], char **err){
    char *out=NULL; int ec=0;
    run_capture(argv,&out,65536,30,&ec);
    if(ec){ *err=out; return 0; }
    free(out); *err=strdup(""); return 1;
}
static void write_managed_quiet(void);
static void clean_stale_managed(void){
    char keep[64][256]; int nkeep=0;
    for(int i=0;i<g_nsites;i++) snprintf(keep[nkeep++],256,"managed-%s.caddy",g_sites[i].domain);
    DIR *d=opendir(SITES_DIR);
    if(d){ struct dirent *e;
        while((e=readdir(d))){
            if(strncmp(e->d_name,"managed-",8)) continue;
            int found=0;
            for(int i=0;i<nkeep;i++) if(!strcmp(keep[i],e->d_name)) found=1;
            if(!found){ char p[512]; snprintf(p,sizeof(p),SITES_DIR "/%s",e->d_name); unlink(p); }
        } closedir(d);
    }
}
static int write_managed(char **err){
    clean_stale_managed();
    for(int i=0;i<g_nsites;i++){
        char p[512]; snprintf(p,sizeof(p),SITES_DIR "/managed-%s.caddy",g_sites[i].domain);
        SB sb; sb_init(&sb); site_snippet(&sb,&g_sites[i]);
        FILE *f=fopen(p,"w"); if(!f){ sb_free(&sb); *err=strdup("cannot write site file"); return 0; }
        fwrite(sb.s,1,sb.len,f); fclose(f); sb_free(&sb);
    }
    char *v1[]={"/usr/bin/caddy","validate","--config",CADDYFILE,NULL};
    if(!caddy_run(v1,err)){ load_sites(); write_managed_quiet(); return 0; }
    char *v2[]={"/usr/bin/caddy","reload","--config",CADDYFILE,NULL};
    if(!caddy_run(v2,err)){ load_sites(); write_managed_quiet();
        char *v3[]={"/usr/bin/caddy","reload","--config",CADDYFILE,NULL}; caddy_run(v3,err); return 0; }
    save_sites();
    return 1;
}
static void write_managed_quiet(void){ /* rollback: rewrite + prune without validation */
    clean_stale_managed();
    for(int i=0;i<g_nsites;i++){
        char p[512]; snprintf(p,sizeof(p),SITES_DIR "/managed-%s.caddy",g_sites[i].domain);
        SB sb; sb_init(&sb); site_snippet(&sb,&g_sites[i]);
        FILE *f=fopen(p,"w"); if(f){ fwrite(sb.s,1,sb.len,f); fclose(f); }
        sb_free(&sb);
    }
}

/* ---------- system stats ---------- */
static pthread_mutex_t g_cpu = PTHREAD_MUTEX_INITIALIZER;
static unsigned long long prev_tot=0, prev_idl=0; static int prev_ok=0;
static struct psnap { pid_t pid; unsigned long long t; } prev_p[2048]; static int prev_pn=0; static double prev_ts=0;

static void meminfo(long *mt, long *ma, long *st, long *sf){
    *mt=*ma=*st=*sf=0; FILE *f=fopen("/proc/meminfo","r"); if(!f) return;
    char k[64]; long v; char line[256];
    while(fgets(line,sizeof(line),f)){
        sscanf(line,"%63s %ld",k,&v);
        if(!strcmp(k,"MemTotal:"))*mt=v; else if(!strcmp(k,"MemAvailable:"))*ma=v;
        else if(!strcmp(k,"SwapTotal:"))*st=v; else if(!strcmp(k,"SwapFree:"))*sf=v;
    }
    fclose(f);
}
static void cpu_total(unsigned long long *tot, unsigned long long *idl){
    *tot=*idl=0; FILE *f=fopen("/proc/stat","r"); if(!f) return;
    char cpu[8]; unsigned long long u,n,i,w,irq,sq,st,g,gn,x;
    if(fscanf(f,"%7s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
        cpu,&u,&n,&i,&w,&irq,&sq,&st,&g,&gn,&x)>=4){
        *tot=u+n+i+w+irq+sq+st; *idl=i+w;
    }
    fclose(f);
}
static int cpu_count=0; static char cpu_model[128]="";
static void read_cpuinfo(void){
    FILE *f=fopen("/proc/cpuinfo","r"); if(!f) return;
    char line[256]; cpu_count=0; cpu_model[0]=0;
    while(fgets(line,sizeof(line),f)){
        if(!strncmp(line,"model name",10)&&!cpu_model[0]){
            char *c=strchr(line,':'); if(c){ c++; c+=strspn(c," \t"); c[strcspn(c,"\n")]=0;
                snprintf(cpu_model,sizeof(cpu_model),"%s",c); } }
        if(!strncmp(line,"processor",9)) cpu_count++;
    }
    fclose(f);
}
static int service_active(const char *svc){
    char cmd[256]; snprintf(cmd,sizeof(cmd),"systemctl is-active %s >/dev/null 2>&1",svc);
    int ec=0; char *o=NULL; char *av[]={"/bin/sh","-c",cmd,NULL};
    run_capture(av,&o,1024,5,&ec); free(o); return ec==0;
}

/* ---------- sessions ---------- */
static int get_session(struct MHD_Connection *c){
    const char *ck=MHD_lookup_connection_value(c,MHD_HEADER_KIND,"Cookie");
    if(!ck) return -1;
    const char *tok=strstr(ck,"pan_token=");
    if(!tok) return -1; tok+=10;
    pthread_mutex_lock(&g_lock);
    time_t now=time(NULL);
    for(int i=0;i<MAX_SESS;i++)
        if(g_sessions[i].token[0]&&!strncmp(g_sessions[i].token,tok,64)&&g_sessions[i].exp>now){
            g_sessions[i].exp=now+43200; pthread_mutex_unlock(&g_lock); return i;
        }
    pthread_mutex_unlock(&g_lock);
    return -1;
}
static void purge_sessions(void){
    time_t now=time(NULL);
    for(int i=0;i<MAX_SESS;i++) if(g_sessions[i].token[0]&&g_sessions[i].exp<now) g_sessions[i].token[0]=0;
}
static IPRec *ip_rec(const char *ip){
    IPRec *free_slot=NULL;
    time_t now=time(NULL);
    for(int i=0;i<g_nips;i++){
        if(!strcmp(g_ips[i].ip,ip)) return &g_ips[i];
        if(!free_slot&&(g_ips[i].n==0||now-g_ips[i].t[g_ips[i].n-1]>600)) free_slot=&g_ips[i];
    }
    if(free_slot){ snprintf(free_slot->ip,sizeof(free_slot->ip),"%s",ip); free_slot->n=0; return free_slot; }
    if(g_nips<MAX_IPS){ IPRec *r=&g_ips[g_nips++]; snprintf(r->ip,sizeof(r->ip),"%s",ip); r->n=0; return r; }
    return &g_ips[0];
}
static void client_ip(struct MHD_Connection *c, char *out, size_t n){
    snprintf(out,n,"%s","?");
    const union MHD_ConnectionInfo *ci=MHD_get_connection_info(c,MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if(!ci||!ci->client_addr) return;
    struct sockaddr *sa=(struct sockaddr*)ci->client_addr;
    char rip[64]="?";
    if(sa->sa_family==AF_INET) inet_ntop(AF_INET,&((struct sockaddr_in*)sa)->sin_addr,rip,sizeof(rip));
    else if(sa->sa_family==AF_INET6) inet_ntop(AF_INET6,&((struct sockaddr_in6*)sa)->sin6_addr,rip,sizeof(rip));
    else return;
    /* behind Caddy (loopback): trust X-Forwarded-For */
    if(!strncmp(rip,"127.",4)||!strcmp(rip,"::1")){
        const char *xff=MHD_lookup_connection_value(c,MHD_HEADER_KIND,"X-Forwarded-For");
        if(xff&&xff[0]){
            char tmp[96]; snprintf(tmp,sizeof(tmp),"%s",xff);
            char *comma=strchr(tmp,','); if(comma)*comma=0;
            char *s=tmp; while(*s==' ')s++;
            if(s[0]) { snprintf(out,n,"%s",s); return; }
        }
    }
    snprintf(out,n,"%s",rip);
}

/* ---------- MHD plumbing ---------- */
struct ci { char *buf; size_t len; };
static void ci_free(void *cls, struct MHD_Connection *c, void **con_cls, enum MHD_RequestTerminationCode r){
    (void)cls;(void)c;(void)r;
    struct ci *ci=*con_cls; if(ci){ free(ci->buf); free(ci); *con_cls=NULL; }
}
static struct MHD_Response *resp_json(SB *b, int code){
    struct MHD_Response *r=MHD_create_response_from_buffer(b->len,b->s,MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(r,"Content-Type","application/json");
    MHD_add_response_header(r,"Cache-Control","no-store");
    MHD_add_response_header(r,"X-Content-Type-Options","nosniff");
    return r;
}
static int respond(struct MHD_Connection *c, int code, const char *ct, char *body, size_t len){
    struct MHD_Response *r=MHD_create_response_from_buffer(len,body,MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(r,"Content-Type",ct);
    MHD_add_response_header(r,"Cache-Control","no-store");
    MHD_add_response_header(r,"X-Content-Type-Options","nosniff");
    int ret=MHD_queue_response(c,code,r);
    MHD_destroy_response(r);
    return ret;
}
static int respond_json(struct MHD_Connection *c, int code, SB *b){
    struct MHD_Response *r=resp_json(b,code);
    int ret=MHD_queue_response(c,code,r); MHD_destroy_response(r); return ret;
}
static int err_json(struct MHD_Connection *c, int code, const char *msg){
    SB b; sb_init(&b); sb_put(&b,"{\"error\":"); sb_json(&b,msg); sb_put(&b,"}");
    return respond_json(c,code,&b);
}
static int require_auth(struct MHD_Connection *c, int *sid){
    *sid=get_session(c);
    if(*sid<0){ err_json(c,401,"unauthorized"); return 0; }
    return 1;
}
/* minimal JSON string-field extractor (client is ours) */
static char *json_str(const char *body, const char *key){
    char pat[128]; snprintf(pat,sizeof(pat),"\"%s\"",key);
    const char *p=strstr(body,pat); if(!p) return NULL;
    p=strchr(p+strlen(pat),':'); if(!p) return NULL; p++;
    while(*p==' ')p++;
    if(isdigit((unsigned char)*p)||*p=='-'){
        /* bare number */
        const char *s=p;
        if(*p=='-')p++;
        while(isdigit((unsigned char)*p))p++;
        SB b; sb_init(&b); sb_putn(&b,s,(size_t)(p-s));
        return b.s;
    }
    if(*p!='"') return NULL; p++;
    SB b; sb_init(&b);
    while(*p&&*p!='"'){
        if(*p=='\\'){
            p++; switch(*p){
            case 'n': sb_putc(&b,'\n'); break; case 't': sb_putc(&b,'\t'); break;
            case 'r': sb_putc(&b,'\r'); break; case '"': sb_putc(&b,'"'); break;
            case '\\': sb_putc(&b,'\\'); break; case '/': sb_putc(&b,'/'); break;
            case 'u': { if(!isxdigit((unsigned char)p[1])){p++;continue;}
                int v=0; for(int i=1;i<=4;i++){ char h=p[i]; v=v*16+(h<='9'?h-'0':(tolower(h)-'a'+10)); }
                if(v<0x80) sb_putc(&b,v);
                else if(v<0x800){ sb_putc(&b,0xC0|(v>>6)); sb_putc(&b,0x80|(v&63)); }
                else { sb_putc(&b,0xE0|v>>12); sb_putc(&b,0x80|(v>>6)&63); sb_putc(&b,0x80|v&63); }
                p+=4; } break;
            default: sb_putc(&b,*p);
            }
        } else sb_putc(&b,*p);
        p++;
    }
    return b.s;
}

/* ---------- route handlers ---------- */
static int h_status(struct MHD_Connection *c){
    long mt,ma,st,sf; meminfo(&mt,&ma,&st,&sf);
    unsigned long long tot,idl; cpu_total(&tot,&idl);
    double cpu_pct=0;
    pthread_mutex_lock(&g_cpu);
    if(prev_ok&&tot>prev_tot){ cpu_pct=100.0*(double)((tot-prev_tot)-(idl-prev_idl))/(double)(tot-prev_tot); if(cpu_pct<0)cpu_pct=0; if(cpu_pct>100)cpu_pct=100; }
    prev_tot=tot; prev_idl=idl; prev_ok=1;
    pthread_mutex_unlock(&g_cpu);
    struct statvfs vfs; statvfs("/",&vfs);
    double loads[3]; getloadavg(loads,3);
    double up; FILE *uf=fopen("/proc/uptime","r"); fscanf(uf,"%lf",&up); fclose(uf);
    struct utsname un; uname(&un);
    read_cpuinfo();
    /* fail2ban */
    int f2b_active=service_active("fail2ban");
    char *o=NULL; int ec=0;
    char *av[]={"/usr/bin/fail2ban-client","status","sshd",NULL};
    run_capture(av,&o,8192,5,&ec);
    int cur_f=0,tot_f=0,cur_b=0,tot_b=0;
    if(!ec&&o){ char *p;
        if((p=strstr(o,"Currently failed"))) cur_f=atoi(p+16);
        if((p=strstr(o,"Total failed"))) tot_f=atoi(p+13);
        if((p=strstr(o,"Currently banned"))) cur_b=atoi(p+17);
        if((p=strstr(o,"Total banned"))) tot_b=atoi(p+13);
    }
    free(o);
    SB b; sb_init(&b);
    sb_fmt(&b,"{\"mem_total\":%ld,\"mem_used\":%ld,\"swap_total\":%ld,\"swap_used\":%ld,"
              "\"disk_total\":%llu,\"disk_used\":%llu,\"load\":[%.2f,%.2f,%.2f],\"uptime_s\":%.0f,"
              "\"cpu_pct\":%.1f,\"cpu_model\":",
        mt*1024,(mt-ma)*1024,st*1024,(st-sf)*1024,
        (unsigned long long)vfs.f_blocks*vfs.f_frsize,(unsigned long long)(vfs.f_blocks-vfs.f_bfree)*vfs.f_frsize,
        loads[0],loads[1],loads[2],up,cpu_pct);
    sb_json(&b,cpu_model);
    sb_fmt(&b,",\"cpu_cores\":%d,\"cpu_arch\":",cpu_count);
    sb_json(&b,un.machine);
    sb_put(&b,",\"f2b\":{");
    sb_fmt(&b,"\"active\":%s,\"cur_f\":%d,\"tot_f\":%d,\"cur_b\":%d,\"tot_b\":%d}",
        f2b_active?"true":"false",cur_f,tot_f,cur_b,tot_b);
    sb_put(&b,",\"services\":{");
    const char *svcs[]={"caddy","panel-c","stockbit-web","systemd-oomd","fail2ban","vnstat"};
    for(size_t i=0;i<sizeof(svcs)/sizeof(*svcs);i++){
        if(i)sb_putc(&b,','); sb_fmt(&b,"\"%s\":",svcs[i]);
        sb_json(&b,service_active(svcs[i])?"active":"inactive");
    }
    sb_put(&b,"}}");
    return respond_json(c,200,&b);
}
static int h_sites(struct MHD_Connection *c){
    SB b; sb_init(&b); sb_put(&b,"{\"sites\":[");
    for(int i=0;i<g_nsites;i++){
        Site *s=&g_sites[i];
        char host[256]; snprintf(host,sizeof(host),"%s",s->target);
        char *colon=strrchr(host,':'); int port=colon?atoi(colon+1):0; if(colon)*colon=0;
        int up=0;
        int fd=socket(AF_INET,SOCK_STREAM,0);
        if(fd>=0){
            struct sockaddr_in sa={0}; sa.sin_family=AF_INET; sa.sin_port=htons(port);
            if(inet_pton(AF_INET,host,&sa.sin_addr)==1){
                struct timeval tv={1,500}; setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
                up=connect(fd,(struct sockaddr*)&sa,sizeof(sa))==0;
            } else {
                struct addrinfo hints={.ai_family=AF_INET},*res;
                if(getaddrinfo(host,NULL,&hints,&res)==0){
                    struct sockaddr_in *a=(struct sockaddr_in*)res->ai_addr;
                    sa.sin_addr=a->sin_addr;
                    struct timeval tv={1,500}; setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
                    up=connect(fd,(struct sockaddr*)&sa,sizeof(sa))==0;
                    freeaddrinfo(res);
                }
            }
            close(fd);
        }
        if(i)sb_putc(&b,',');
        sb_fmt(&b,"{\"domain\":"); sb_json(&b,s->domain);
        sb_fmt(&b,",\"target\":"); sb_json(&b,s->target);
        sb_fmt(&b,",\"auth_user\":"); sb_json(&b,s->auth_user);
        sb_fmt(&b,",\"extra\":"); sb_json(&b,s->extra);
        sb_fmt(&b,",\"upstream_alive\":%s}",up?"true":"false");
    }
    sb_put(&b,"]}");
    return respond_json(c,200,&b);
}
static int h_add_site(struct MHD_Connection *c, const char *body){
    char *domain=json_str(body,"domain"), *target=json_str(body,"target");
    char *au=json_str(body,"auth_user"), *ap=json_str(body,"auth_pass");
    char *extra=json_str(body,"extra");
    if(!domain||!target){ free(domain);free(target);free(au);free(ap);free(extra); return err_json(c,400,"missing fields"); }
    for(char *p=domain;*p;p++)*p=tolower(*p);
    for(char *p=target;*p;p++)*p=tolower(*p);
    if(!valid_domain(domain)){ free(domain);free(target);free(au);free(ap);free(extra); return err_json(c,400,"invalid domain"); }
    if(!valid_target(target)){ free(domain);free(target);free(au);free(ap);free(extra); return err_json(c,400,"target must be host:port"); }
    for(int i=0;i<g_nsites;i++) if(!strcmp(g_sites[i].domain,domain)){
        free(domain);free(target);free(au);free(ap);free(extra); return err_json(c,409,"domain already exists"); }
    Site *s=&g_sites[g_nsites];
    snprintf(s->domain,sizeof(s->domain),"%s",domain);
    snprintf(s->target,sizeof(s->target),"%s",target);
    s->auth_user[0]=0; s->auth_hash[0]=0;
    snprintf(s->extra,sizeof(s->extra),"%s",extra?extra:"");
    if((au&&au[0])||(ap&&ap[0])){
        if(!au||!valid_user(au)||!ap||strlen(ap)<8){
            free(domain);free(target);free(au);free(ap);
            return err_json(c,400,"auth user invalid or password too short (min 8)");
        }
        char *av[]={"/usr/bin/caddy","hash-password","--plaintext",ap,NULL};
        char *o=NULL; int ec=0;
        run_capture(av,&o,4096,15,&ec);
        if(ec||!o||!o[0]){ free(o); free(domain);free(target);free(au);free(ap);
            return err_json(c,400,"failed to hash password"); }
        o[strcspn(o,"\r\n")]=0;
        snprintf(s->auth_user,sizeof(s->auth_user),"%s",au);
        snprintf(s->auth_hash,sizeof(s->auth_hash),"%s",o);
        free(o);
    }
    g_nsites++;
    char *err=NULL;
    if(!write_managed(&err)){
        char msg[512]; snprintf(msg,sizeof(msg),"caddy: %.200s",err?err:"failed");
        free(err); free(domain);free(target);free(au);free(ap);
        return err_json(c,400,msg);
    }
    free(err); free(domain);free(target);free(au);free(ap);free(extra);
    SB b; sb_init(&b); sb_put(&b,"{\"ok\":true}");
    return respond_json(c,200,&b);
}
static int h_site_update(struct MHD_Connection *c, const char *body){
    char *domain=json_str(body,"domain"), *target=json_str(body,"target");
    char *extra=json_str(body,"extra");
    char *au=json_str(body,"auth_user"), *ap=json_str(body,"auth_pass");
    if(!domain||!valid_domain(domain)){ free(domain);free(target);free(extra);free(au);free(ap); return err_json(c,400,"invalid domain"); }
    int idx=-1;
    for(int i=0;i<g_nsites;i++) if(!strcmp(g_sites[i].domain,domain)) idx=i;
    if(idx<0){ free(domain);free(target);free(extra);free(au);free(ap); return err_json(c,404,"not found"); }
    Site *s=&g_sites[idx];
    if(target){
        if(!valid_target(target)){ free(domain);free(target);free(extra);free(au);free(ap); return err_json(c,400,"target must be host:port"); }
        snprintf(s->target,sizeof(s->target),"%s",target);
    }
    if(extra) snprintf(s->extra,sizeof(s->extra),"%s",extra);
    if((au&&au[0])||(ap&&ap[0])){
        if(!au||!valid_user(au)||!ap||strlen(ap)<8){
            free(domain);free(target);free(extra);free(au);free(ap);
            return err_json(c,400,"auth user invalid or password too short (min 8)");
        }
        char *av[]={"/usr/bin/caddy","hash-password","--plaintext",ap,NULL};
        char *o=NULL; int ec=0;
        run_capture(av,&o,4096,15,&ec);
        if(ec||!o||!o[0]){ free(o);free(domain);free(target);free(extra);free(au);free(ap);
            return err_json(c,400,"failed to hash password"); }
        o[strcspn(o,"\r\n")]=0;
        snprintf(s->auth_user,sizeof(s->auth_user),"%s",au);
        snprintf(s->auth_hash,sizeof(s->auth_hash),"%s",o);
        free(o);
    } else if(au) { s->auth_user[0]=0; s->auth_hash[0]=0; }
    char *err=NULL;
    if(!write_managed(&err)){
        char msg[512]; snprintf(msg,sizeof(msg),"caddy: %.200s",err?err:"failed");
        free(err); free(domain);free(target);free(extra);free(au);free(ap);
        return err_json(c,400,msg);
    }
    free(err); free(domain);free(target);free(extra);free(au);free(ap);
    SB b; sb_init(&b); sb_put(&b,"{\"ok\":true}");
    return respond_json(c,200,&b);
}
static int h_caddy_validate(struct MHD_Connection *c, const char *body){
    char *domain=json_str(body,"domain"), *target=json_str(body,"target"), *extra=json_str(body,"extra");
    if(!domain||!target){ free(domain);free(target);free(extra); return err_json(c,400,"missing fields"); }
    for(char *p=domain;*p;p++)*p=tolower(*p);
    if(!valid_domain(domain)){ free(domain);free(target);free(extra); return err_json(c,400,"invalid domain"); }
    /* build standalone candidate snippet */
    Site tmp; memset(&tmp,0,sizeof(tmp));
    snprintf(tmp.domain,sizeof(tmp.domain),"%s",domain);
    snprintf(tmp.target,sizeof(tmp.target),"%s",target);
    snprintf(tmp.extra,sizeof(tmp.extra),"%s",extra?extra:"");
    SB sn; sb_init(&sn); site_snippet(&sn,&tmp);
    char tf[128]= "/tmp/panel-validate-XXXXXX.caddy";
    int fd=mkstemps(tf,6);   /* trailing ".caddy" */
    if(fd<0){ free(domain);free(target);free(extra); sb_free(&sn); return err_json(c,500,"mkstemp failed"); }
    write(fd,sn.s,sn.len); close(fd); sb_free(&sn);
    char *av[]={"/usr/bin/caddy","validate","--config",tf,"--adapter","caddyfile",NULL};
    char *o=NULL; int ec=0;
    run_capture(av,&o,65536,20,&ec);
    unlink(tf);
    SB b; sb_init(&b);
    if(ec){
        sb_put(&b,"{\"ok\":false,\"error\":"); sb_json(&b,o?o:"unknown error"); sb_put(&b,"}");
    } else {
        sb_put(&b,"{\"ok\":true}");
    }
    free(o); free(domain);free(target);free(extra);
    return respond_json(c,200,&b);
}
static int h_del_site(struct MHD_Connection *c, const char *domain){
    for(char *p=(char*)domain;*p;p++)
        if(!(islower((unsigned char)*p)||isdigit((unsigned char)*p)||*p=='.'||*p=='-'))
            return err_json(c,400,"invalid domain");
    int idx=-1;
    for(int i=0;i<g_nsites;i++) if(!strcmp(g_sites[i].domain,domain)) idx=i;
    if(idx<0) return err_json(c,404,"not found");
    for(int i=idx;i<g_nsites-1;i++) g_sites[i]=g_sites[i+1];
    g_nsites--;
    char *err=NULL;
    if(!write_managed(&err)){ char msg[512]; snprintf(msg,sizeof(msg),"caddy: %.200s",err?err:"failed"); free(err); return err_json(c,400,msg); }
    free(err);
    SB b; sb_init(&b); sb_put(&b,"{\"ok\":true}");
    return respond_json(c,200,&b);
}
static int h_exec(struct MHD_Connection *c, const char *body){
    char *cmd=json_str(body,"command");
    if(!cmd||!cmd[0]){ free(cmd); return err_json(c,400,"empty command"); }
    char *out=NULL; int ec=0;
    char *av[]={"/bin/bash","-c",cmd,NULL};
    run_capture(av,&out,MAX_OUTPUT,EXEC_TIMEOUT,&ec);
    SB b; sb_init(&b);
    sb_fmt(&b,"{\"ok\":true,\"exit\":%d,\"output\":",ec);
    sb_json(&b,out?out:""); sb_put(&b,"}");
    free(out); free(cmd);
    return respond_json(c,200,&b);
}
typedef struct { int pid; double cpu; long rss; char user[40]; char cmd[258]; } ProcRow;
static int procs_cmp(const void *a, const void *b){
    return ((const ProcRow*)b)->cpu>((const ProcRow*)a)->cpu?1:-1;
}
static int h_processes(struct MHD_Connection *c){
    /* heap, not stack: ~200KB would overflow the 192KB MHD thread stack */
    ProcRow *rows=malloc(sizeof(ProcRow)*512);
    struct psnap *cur=malloc(sizeof(struct psnap)*2048);
    if(!rows||!cur){ free(rows); free(cur); return err_json(c,500,"oom"); }
    int n=0;
    double now=0; FILE *uf=fopen("/proc/uptime","r"); if(uf){ fscanf(uf,"%lf",&now); fclose(uf); }
    int curn=0; unsigned long long hz=sysconf(_SC_CLK_TCK);
    DIR *d=opendir("/proc");
    if(!d){ free(rows); free(cur); return err_json(c,500,"opendir failed"); }
    struct dirent *e;
    while((e=readdir(d))&&curn<2048){
        if(!isdigit((unsigned char)e->d_name[0])) continue;
        int pid=atoi(e->d_name);
        char path[64]; snprintf(path,sizeof(path),"/proc/%d/stat",pid);
        FILE *f=fopen(path,"r"); if(!f) continue;
        char buf[2048]; if(!fgets(buf,sizeof(buf),f)){ fclose(f); continue; }
        fclose(f);
        char *rp=strrchr(buf,')'); if(!rp) continue;
        unsigned long long u2,s2; long rs2; unsigned long long ut=0,stk=0; long rss_pages=0;
        sscanf(rp+2,"%*c %*d %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu %llu %*s %*s %*s %*s %*s %*s %*s %ld",
               &u2,&s2,&rs2);
        ut=u2; stk=s2; rss_pages=rs2;        snprintf(path,sizeof(path),"/proc/%d/cmdline",pid);
        char cmd[258]=""; f=fopen(path,"r");
        if(f){ size_t k=fread(cmd,1,250,f); if(!k) snprintf(cmd,sizeof(cmd),"[%s]","?"); fclose(f);
               cmd[k]=0; for(size_t z=0;z<k;z++) if(cmd[z]==0)cmd[z]=' '; }
        struct stat stt; char user[40]="?";
        if(!stat(path,&stt)){ struct passwd *pw=getpwuid(stt.st_uid); snprintf(user,sizeof(user),"%s",pw?pw->pw_name:"?"); }
        /* find prev ticks */
        unsigned long long prev=0;
        for(int i=0;i<prev_pn;i++) if(prev_p[i].pid==pid){ prev=prev_p[i].t; break; }
        unsigned long long ticks=ut+stk;
        cur[curn].pid=pid; cur[curn].t=ticks; curn++;
        double dt=now-prev_ts;
        double cpupct = (prev_ts>0&&dt>0&&ticks>=prev)?(100.0*(double)(ticks-prev)/hz/dt):0;
        if(cpupct>999)cpupct=999;
        if(n<512){
            rows[n].pid=pid; rows[n].cpu=cpupct; rows[n].rss=rss_pages*4;
            snprintf(rows[n].user,sizeof(rows[n].user),"%s",user);
            snprintf(rows[n].cmd,sizeof(rows[n].cmd),"%s",cmd[0]?cmd:"[kernel]");
            n++;
        }
    }
    closedir(d);
    pthread_mutex_lock(&g_cpu);
    memcpy(prev_p,cur,sizeof(struct psnap)*curn); prev_pn=curn; prev_ts=now;
    pthread_mutex_unlock(&g_cpu);
    qsort(rows,n,sizeof(ProcRow),procs_cmp);
    SB b; sb_init(&b); sb_put(&b,"{\"processes\":[");
    int shown=0;
    for(int i=0;i<n&&shown<40;i++){
        if(i)sb_putc(&b,',');
        sb_fmt(&b,"{\"pid\":%d,\"cpu\":%.1f,\"rss\":%ld,\"user\":",rows[i].pid,rows[i].cpu,rows[i].rss);
        sb_json(&b,rows[i].user);
        sb_put(&b,",\"cmd\":"); sb_json(&b,rows[i].cmd); sb_put(&b,"}");
        shown++;
    }
    sb_put(&b,"]}");
    free(rows); free(cur);
    return respond_json(c,200,&b);
}
static int h_kill(struct MHD_Connection *c, const char *body){
    char *ps=json_str(body,"pid");
    if(!ps){ return err_json(c,400,"missing pid"); }
    int pid=atoi(ps); free(ps);
    if(pid<=1||pid==getpid()||pid==getppid()) return err_json(c,400,"refusing to kill that pid");
    if(kill(pid,SIGKILL)) return err_json(c,400,"kill failed");
    SB b; sb_init(&b); sb_put(&b,"{\"ok\":true}");
    return respond_json(c,200,&b);
}
static int h_services(struct MHD_Connection *c){
    char *o=NULL; int ec=0;
    char *av[]={"/bin/sh","-c","systemctl list-units --type=service --all --no-legend --no-pager",NULL};
    run_capture(av,&o,131072,15,&ec);
    SB b; sb_init(&b); sb_put(&b,"{\"services\":[");
    int first=1;
    if(o){
        for(char *line=strtok(o,"\n"); line; line=strtok(NULL,"\n")){
            char unit[128]="",load[32]="",act[32]="",sub[32]="",desc[256]="";
            if(sscanf(line,"%127s %31s %31s %31s %255[^\n]",unit,load,act,sub,desc)!=5) continue;
            if(!strstr(unit,".service")) continue;
            if(!first)sb_putc(&b,','); first=0;
            sb_fmt(&b,"{\"unit\":"); sb_json(&b,unit);
            sb_fmt(&b,",\"active\":"); sb_json(&b,act);
            sb_fmt(&b,",\"sub\":"); sb_json(&b,sub);
            sb_fmt(&b,",\"desc\":"); sb_json(&b,desc);
            sb_put(&b,"}");
        }
    }
    free(o);
    sb_put(&b,"]}");
    return respond_json(c,200,&b);
}
/* ---------- listening ports ---------- */
typedef struct { int port; char proto[8]; long inode; int pid; char proc[128]; char user[40]; int est; } PortRow;
static int ports_cmp(const void *a, const void *b){
    const PortRow *x=a, *y=b;
    if(x->port!=y->port) return x->port-y->port;
    return strcmp(x->proto,y->proto);
}
static int h_ports(struct MHD_Connection *c){
    PortRow *rows=calloc(256,sizeof(PortRow)); int n=0;
    const char *files[]={"/proc/net/tcp","/proc/net/tcp6"};
    const char *protos[]={"tcp","tcp6"};
    for(int fi=0;fi<2;fi++){
        FILE *f=fopen(files[fi],"r"); if(!f) continue;
        char line[512]; int first=1;
        while(fgets(line,sizeof(line),f)&&n<256){
            if(first){first=0;continue;}
            char local[128]="", st[32]=""; long inode=-1;
            if(sscanf(line,"%*d: %127s %*s %31s %*s %*s %*s %*d %*d %ld",local,st,&inode)!=3) continue;
            if(strcmp(st,"0A")) continue;                    /* 0A = LISTEN */
            char *cp=strrchr(local,':'); if(!cp) continue;
            rows[n].port=(int)strtoul(cp+1,NULL,16);
            snprintf(rows[n].proto,8,"%s",protos[fi]);
            rows[n].inode=inode; rows[n].pid=0; rows[n].est=0;
            rows[n].proc[0]=0; rows[n].user[0]=0; n++;
        }
        fclose(f);
    }
    /* established connection counts per listening port */
    for(int fi=0;fi<2;fi++){
        FILE *f=fopen(files[fi],"r"); if(!f) continue;
        char line[512]; int first=1;
        while(fgets(line,sizeof(line),f)){
            if(first){first=0;continue;}
            char local[128]="", st[32]="";
            if(sscanf(line,"%*d: %127s %*s %31s",local,st)!=2) continue;
            if(strcmp(st,"01")) continue;                    /* 01 = ESTABLISHED */
            char *cp=strrchr(local,':'); if(!cp) continue;
            int port=(int)strtoul(cp+1,NULL,16);
            for(int i=0;i<n;i++)
                if(rows[i].port==port&&!strcmp(rows[i].proto,protos[fi])) rows[i].est++;
        }
        fclose(f);
    }
    /* inode -> owning process */
    DIR *d=opendir("/proc"); struct dirent *e;
    while((e=readdir(d))){
        if(!isdigit((unsigned char)e->d_name[0])) continue;
        int pid=atoi(e->d_name);
        char fdpath[96]; snprintf(fdpath,sizeof(fdpath),"/proc/%d/fd",pid);
        DIR *fd=opendir(fdpath); if(!fd) continue;
        struct dirent *fe;
        while((fe=readdir(fd))){
            char link[160], target[300];
            snprintf(link,sizeof(link),"%s/%s",fdpath,fe->d_name);
            ssize_t k=readlink(link,target,sizeof(target)-1); if(k<=0) continue;
            target[k]=0;
            if(strncmp(target,"socket:[",8)) continue;
            long ino=strtol(target+8,NULL,10);
            for(int i=0;i<n;i++){
                if(rows[i].pid||rows[i].inode!=ino) continue;
                rows[i].pid=pid;
                char cpath[96]; snprintf(cpath,sizeof(cpath),"/proc/%d/comm",pid);
                FILE *cf=fopen(cpath,"r");
                if(cf){ char cm[128];
                    if(fgets(cm,sizeof(cm),cf)){ cm[strcspn(cm,"\n")]=0; snprintf(rows[i].proc,128,"%s",cm); }
                    fclose(cf); }
                if(!rows[i].proc[0]) snprintf(rows[i].proc,128,"pid %d",pid);
                struct stat stt; struct passwd *pw;
                if(!stat(fdpath,&stt)){ pw=getpwuid(stt.st_uid);
                    snprintf(rows[i].user,40,"%s",pw?pw->pw_name:"?"); }
            }
        }
        closedir(fd);
    }
    closedir(d);
    qsort(rows,n,sizeof(PortRow),ports_cmp);
    SB b; sb_init(&b); sb_put(&b,"{\"ports\":[");
    for(int i=0;i<n;i++){
        if(i)sb_putc(&b,',');
        sb_fmt(&b,"{\"port\":%d,\"proto\":",rows[i].port); sb_json(&b,rows[i].proto);
        sb_fmt(&b,",\"pid\":%d,\"proc\":",rows[i].pid);   sb_json(&b,rows[i].proc[0]?rows[i].proc:"?");
        sb_fmt(&b,",\"user\":");                          sb_json(&b,rows[i].user[0]?rows[i].user:"?");
        sb_fmt(&b,",\"est\":%d}",rows[i].est);
    }
    sb_put(&b,"]}");
    free(rows);
    return respond_json(c,200,&b);
}
/* ---------- file manager ---------- */
typedef struct { char name[512]; int dir,link; long long size; long long mtime; unsigned mode; } FE;
static int fe_cmp(const void *a, const void *b){
    const FE *x=a, *y=b;
    if(x->dir!=y->dir) return y->dir-x->dir;   /* dirs first */
    return strcmp(x->name,y->name);
}
static int sane_path(const char *p){ return p && p[0]=='/' && strlen(p)<4096; }
static int rm_cb(const char *f, const struct stat *st, int flag, struct FTW *fw){
    (void)st;(void)flag;(void)fw;
    return remove(f);
}
static int b64val(char c){
    if(c>='A'&&c<='Z')return c-'A'; if(c>='a'&&c<='z')return c-'a'+26;
    if(c>='0'&&c<='9')return c-'0'+52; if(c=='+')return 62; if(c=='/')return 63; return -1;
}
static unsigned char *b64decode(const char *in, size_t *outlen){
    size_t n=strlen(in); unsigned char *out=malloc(n/4*3+4); size_t o=0;
    int quad=0; unsigned acc=0;
    for(size_t i=0;i<n;i++){
        int v=b64val(in[i]); if(v<0){ if(in[i]=='=') break; continue; }
        acc=(acc<<6)|(unsigned)v;
        if(++quad==4){ out[o++]=(acc>>16)&255; out[o++]=(acc>>8)&255; out[o++]=acc&255; quad=0; acc=0; }
    }
    if(quad==2){ out[o++]=(acc>>4)&255; } else if(quad==3){ out[o++]=(acc>>10)&255; out[o++]=(acc>>2)&255; }
    *outlen=o; return out;
}
static int h_files(struct MHD_Connection *c){
    const char *path=MHD_lookup_connection_value(c,MHD_GET_ARGUMENT_KIND,"path");
    if(!sane_path(path)) return err_json(c,400,"invalid path");
    DIR *d=opendir(path); if(!d) return err_json(c,404,"cannot open directory");
    FE *fe=calloc(1024,sizeof(FE)); int n=0;
    struct dirent *e;
    while((e=readdir(d))&&n<1024){
        if(!strcmp(e->d_name,".")||!strcmp(e->d_name,"..")) continue;
        FE *r=&fe[n];
        snprintf(r->name,512,"%s",e->d_name);
        char full[4224]; snprintf(full,sizeof(full),"%s/%s",path,e->d_name);
        struct stat st={0};
        if(lstat(full,&st)) continue;
        r->dir=S_ISDIR(st.st_mode); r->link=S_ISLNK(st.st_mode);
        r->size=(long long)st.st_size; r->mtime=(long long)st.st_mtime;
        r->mode=(unsigned)(st.st_mode&07777);
        n++;
    }
    closedir(d);
    qsort(fe,n,sizeof(FE),fe_cmp);
    SB b; sb_init(&b); sb_put(&b,"{\"path\":"); sb_json(&b,path); sb_put(&b,",\"entries\":[");
    for(int i=0;i<n;i++){
        if(i)sb_putc(&b,',');
        sb_fmt(&b,"{\"name\":"); sb_json(&b,fe[i].name);
        sb_fmt(&b,",\"dir\":%s,\"link\":%s,\"size\":%lld,\"mtime\":%lld,\"mode\":%o}",
            fe[i].dir?"true":"false",fe[i].link?"true":"false",fe[i].size,fe[i].mtime,fe[i].mode);
    }
    sb_put(&b,"]}");
    free(fe);
    return respond_json(c,200,&b);
}
static int h_file_view(struct MHD_Connection *c){
    const char *path=MHD_lookup_connection_value(c,MHD_GET_ARGUMENT_KIND,"path");
    if(!sane_path(path)) return err_json(c,400,"invalid path");
    struct stat st;
    if(stat(path,&st)||S_ISDIR(st.st_mode)) return err_json(c,404,"not a regular file");
    if(st.st_size>512*1024) return err_json(c,400,"file too large to edit (>512KB), use download or terminal");
    FILE *f=fopen(path,"rb"); if(!f) return err_json(c,403,"cannot open file");
    char *buf=malloc((size_t)st.st_size+1);
    size_t rd=fread(buf,1,(size_t)st.st_size,f); fclose(f); buf[rd]=0;
    SB b; sb_init(&b); sb_put(&b,"{\"ok\":true,\"content\":"); sb_json(&b,buf); sb_put(&b,"}");
    free(buf);
    return respond_json(c,200,&b);
}
static int h_file_download(struct MHD_Connection *c){
    const char *path=MHD_lookup_connection_value(c,MHD_GET_ARGUMENT_KIND,"path");
    if(!sane_path(path)) return err_json(c,400,"invalid path");
    struct stat st;
    if(stat(path,&st)||!S_ISREG(st.st_mode)) return err_json(c,404,"not a regular file");
    if(st.st_size>16*1024*1024) return err_json(c,400,"file >16MB, use terminal (scp/curl)");
    FILE *f=fopen(path,"rb"); if(!f) return err_json(c,403,"cannot open file");
    char *buf=malloc((size_t)st.st_size+1);
    size_t rd=fread(buf,1,(size_t)st.st_size,f); fclose(f);
    struct MHD_Response *r=MHD_create_response_from_buffer(rd,buf,MHD_RESPMEM_MUST_FREE);
    const char *bn=strrchr(path,'/'); bn=bn?bn+1:path;
    char cd[300]; snprintf(cd,sizeof(cd),"attachment; filename=\"%s\"",bn);
    MHD_add_response_header(r,"Content-Type","application/octet-stream");
    MHD_add_response_header(r,"Content-Disposition",cd);
    int ret=MHD_queue_response(c,200,r); MHD_destroy_response(r); return ret;
}
static int h_file_save(struct MHD_Connection *c, const char *body){
    char *path=json_str(body,"path"), *content=json_str(body,"content");
    if(!sane_path(path)||!content){ free(path);free(content); return err_json(c,400,"invalid path/content"); }
    struct stat st; if(!stat(path,&st)&&S_ISDIR(st.st_mode)){ free(path);free(content); return err_json(c,400,"path is a directory"); }
    FILE *f=fopen(path,"w");
    if(!f){ free(path);free(content); return err_json(c,403,"cannot write file"); }
    fwrite(content,1,strlen(content),f); fclose(f);
    free(path);free(content);
    SB b; sb_init(&b); sb_put(&b,"{\"ok\":true}");
    return respond_json(c,200,&b);
}
static int h_file_mkdir(struct MHD_Connection *c, const char *body){
    char *path=json_str(body,"path");
    if(!sane_path(path)){ free(path); return err_json(c,400,"invalid path"); }
    if(mkdir(path,0755)&&errno!=EEXIST){ free(path); return err_json(c,400,"mkdir failed"); }
    free(path);
    SB b; sb_init(&b); sb_put(&b,"{\"ok\":true}");
    return respond_json(c,200,&b);
}
static int h_file_delete(struct MHD_Connection *c, const char *body){
    char *path=json_str(body,"path");
    if(!sane_path(path)){ free(path); return err_json(c,400,"invalid path"); }
    char rp[4096]; if(!realpath(path,rp)||!strcmp(rp,"/")){
        free(path); return err_json(c,400,"refusing to delete /"); }
    if(unlink(path)&&errno==EISDIR){
        if(nftw(path,rm_cb,32,FTW_PHYS|FTW_DEPTH)){ free(path); return err_json(c,400,"delete failed"); }
    } else if(errno!=ENOENT && unlink(path)){ free(path); return err_json(c,400,"delete failed"); }
    free(path);
    SB b; sb_init(&b); sb_put(&b,"{\"ok\":true}");
    return respond_json(c,200,&b);
}
static int h_file_rename(struct MHD_Connection *c, const char *body){
    char *from=json_str(body,"from"), *to=json_str(body,"to");
    if(!sane_path(from)||!sane_path(to)){ free(from);free(to); return err_json(c,400,"invalid path"); }
    if(!access(to,F_OK)){ free(from);free(to); return err_json(c,400,"target already exists"); }
    if(rename(from,to)){ free(from);free(to); return err_json(c,400,"rename failed"); }
    free(from);free(to);
    SB b; sb_init(&b); sb_put(&b,"{\"ok\":true}");
    return respond_json(c,200,&b);
}
static int h_file_upload(struct MHD_Connection *c, const char *body){
    char *path=json_str(body,"path"), *b64=json_str(body,"b64");
    if(!sane_path(path)||!b64){ free(path);free(b64); return err_json(c,400,"invalid path/content"); }
    size_t dl=0; unsigned char *data=b64decode(b64,&dl);
    if(!data||dl>8*1024*1024){ free(data);free(path);free(b64); return err_json(c,400,"empty or >8MB"); }
    FILE *f=fopen(path,"wb");
    if(!f){ free(data);free(path);free(b64); return err_json(c,403,"cannot write file"); }
    fwrite(data,1,dl,f); fclose(f); free(data); free(path); free(b64);
    SB b; sb_init(&b); sb_put(&b,"{\"ok\":true}");
    return respond_json(c,200,&b);
}
static int h_service_action(struct MHD_Connection *c, const char *body){    char *name=json_str(body,"name"), *act=json_str(body,"action");
    if(!name||!act){ free(name);free(act); return err_json(c,400,"missing fields"); }
    for(char *p=name;*p;p++){ char ch=*p;
        if(!(isalnum((unsigned char)ch)||ch=='@'||ch=='.'||ch=='_'||ch=='-')){
            free(name);free(act); return err_json(c,400,"invalid unit name"); } }
    if(strcmp(act,"start")&&strcmp(act,"stop")&&strcmp(act,"restart")){
        free(name);free(act); return err_json(c,400,"invalid action"); }
    char *o=NULL; int ec=0;
    char *av[]={"/bin/systemctl",(char*)act,name,NULL};
    run_capture(av,&o,65536,30,&ec);
    free(o); free(name); free(act);
    if(ec) return err_json(c,400,"systemctl failed");
    SB b; sb_init(&b); sb_put(&b,"{\"ok\":true}");
    return respond_json(c,200,&b);
}
static int h_password(struct MHD_Connection *c, const char *body){
    char *cur=json_str(body,"current"), *nw=json_str(body,"new");
    if(!cur||!nw){ free(cur);free(nw); return err_json(c,400,"missing fields"); }
    if(!check_pw(cur)){ free(cur);free(nw); return err_json(c,403,"current password wrong"); }
    if(strlen(nw)<10){ free(cur);free(nw); return err_json(c,400,"new password must be at least 10 characters"); }
    char rnd[23], salt[40];
    rnd_str(rnd,22,B64);
    snprintf(salt,sizeof(salt),"$2b$10$%s",rnd);
    struct crypt_data d={.initialized=0};
    char *h=crypt_r(nw,salt,&d);
    FILE *f=fopen(CONFIG_PATH,"w"); fprintf(f,"hash=%s\n",h); fclose(f);
    chmod(CONFIG_PATH,0600);
    snprintf(g_hash,sizeof(g_hash),"%s",h);
    free(cur); free(nw);
    SB b; sb_init(&b); sb_put(&b,"{\"ok\":true}");
    return respond_json(c,200,&b);
}

/* ---------- dispatcher ---------- */
static enum MHD_Result ahc(void *cls, struct MHD_Connection *c, const char *url,
                           const char *method, const char *ver,
                           const char *ud, size_t *usz, void **con_cls){
    (void)cls;(void)ver;
    struct ci *ci=*con_cls;
    if(!ci){ ci=calloc(1,sizeof(struct ci)); *con_cls=ci; return MHD_YES; }
    int is_post=!strcmp(method,"POST");
    if(is_post&&*usz>0){
        ci->buf=realloc(ci->buf,ci->len+*usz+1);
        memcpy(ci->buf+ci->len,ud,*usz); ci->len+=*usz; ci->buf[ci->len]=0;
        *usz=0;
        if(ci->len>16*1024*1024) return MHD_NO;
        return MHD_YES;
    }
    int sid=get_session(c);
    int authed=sid>=0;
    const char *body=ci->buf?ci->buf:"";   /* zero-copy: ci->buf is NUL-terminated */

    if(!strcmp(url,"/")&&!strcmp(method,"GET")){
        FILE *f=fopen(HTML_PATH,"r");
        if(!f) return respond(c,404,"text/plain",strdup("missing index.html"),17);
        fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
        char *html=malloc(n+1); fread(html,1,n,f); fclose(f); html[n]=0;
        return respond(c,200,"text/html; charset=utf-8",html,n);
    }
    if(!strcmp(url,"/api/me")){
        SB b; sb_init(&b); sb_fmt(&b,"{\"authenticated\":%s}",authed?"true":"false");
        return respond_json(c,200,&b);
    }
    if(!strcmp(url,"/api/login")&&is_post){
        /* CSRF-lite: our client sends this header */
        const char *x=MHD_lookup_connection_value(c,MHD_HEADER_KIND,"X-Requested-With");
        if(!x||strcmp(x,"fetch")) return err_json(c,403,"bad request");
        char ip[64]; client_ip(c,ip,sizeof(ip));
        pthread_mutex_lock(&g_lock);
        IPRec *r=ip_rec(ip);
        time_t now=time(NULL);
        int k=0;
        for(int i=0;i<r->n;i++) if(now-r->t[i]<300) r->t[k++]=r->t[i];
        r->n=k;
        int blocked=r->n>=5;
        pthread_mutex_unlock(&g_lock);
        if(blocked) return err_json(c,429,"too many failed attempts from your IP, wait 5 minutes");
        char *pw=json_str(body,"password");
        if(pw&&check_pw(pw)){
            free(pw);
            pthread_mutex_lock(&g_lock);
            purge_sessions();
            r->n=0;
            int slot=-1; for(int i=0;i<MAX_SESS;i++) if(!g_sessions[i].token[0]){slot=i;break;}
            if(slot<0) slot=random()%MAX_SESS;
            char tok[65]; rnd_str(tok,64,"0123456789abcdef");
            snprintf(g_sessions[slot].token,65,"%s",tok);
            g_sessions[slot].exp=now+43200;
            pthread_mutex_unlock(&g_lock);
            char ck[128]; snprintf(ck,sizeof(ck),"pan_token=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200",tok);
            SB b; sb_init(&b); sb_put(&b,"{\"ok\":true}");
            struct MHD_Response *rr=resp_json(&b,200);
            MHD_add_response_header(rr,"Set-Cookie",ck);
            int ret=MHD_queue_response(c,200,rr); MHD_destroy_response(rr); return ret;
        }
        free(pw);
        pthread_mutex_lock(&g_lock);
        if(r->n<8) r->t[r->n++]=now;
        pthread_mutex_unlock(&g_lock);
        return err_json(c,401,"wrong password");
    }
    if(!strcmp(url,"/api/logout")&&is_post){
        if(sid>=0){ pthread_mutex_lock(&g_lock); g_sessions[sid].token[0]=0; pthread_mutex_unlock(&g_lock); }
        SB b; sb_init(&b); sb_put(&b,"{\"ok\":true}");
        return respond_json(c,200,&b);
    }
    /* everything below requires auth */
    if(!authed) return err_json(c,401,"unauthorized");
    const char *x=MHD_lookup_connection_value(c,MHD_HEADER_KIND,"X-Requested-With");
    if(is_post&&(!x||strcmp(x,"fetch"))) return err_json(c,403,"bad request");

    if(!strcmp(url,"/api/status")&&!strcmp(method,"GET")){ int r=h_status(c); trim_heap(); return r; }
    if(!strcmp(url,"/api/sites")&&!strcmp(method,"GET")){ int r=h_sites(c); trim_heap(); return r; }
    if(!strcmp(url,"/api/sites")&&is_post){ int r=h_add_site(c,body); trim_heap(); return r; }
    if(!strcmp(url,"/api/sites/update")&&is_post){ int r=h_site_update(c,body); trim_heap(); return r; }
    if(!strcmp(url,"/api/caddy/validate")&&is_post){ int r=h_caddy_validate(c,body); trim_heap(); return r; }
    if(!strncmp(url,"/api/sites/",11)&&!strcmp(method,"DELETE")){ int r=h_del_site(c,url+11); trim_heap(); return r; }
    if(!strcmp(url,"/api/exec")&&is_post){ int r=h_exec(c,body); trim_heap(); return r; }
    if(!strcmp(url,"/api/processes")&&!strcmp(method,"GET")){ int r=h_processes(c); trim_heap(); return r; }
    if(!strcmp(url,"/api/ports")&&!strcmp(method,"GET")){ int r=h_ports(c); trim_heap(); return r; }
    if(!strcmp(url,"/api/files")&&!strcmp(method,"GET")){ int r=h_files(c); trim_heap(); return r; }
    if(!strcmp(url,"/api/file/view")&&!strcmp(method,"GET")) return h_file_view(c);
    if(!strcmp(url,"/api/file/download")&&!strcmp(method,"GET")) return h_file_download(c);
    if(!strcmp(url,"/api/file/save")&&is_post) return h_file_save(c,body);
    if(!strcmp(url,"/api/file/mkdir")&&is_post) return h_file_mkdir(c,body);
    if(!strcmp(url,"/api/file/delete")&&is_post) return h_file_delete(c,body);
    if(!strcmp(url,"/api/file/rename")&&is_post) return h_file_rename(c,body);
    if(!strcmp(url,"/api/file/upload")&&is_post) return h_file_upload(c,body);
    if(!strcmp(url,"/api/kill")&&is_post) return h_kill(c,body);
    if(!strcmp(url,"/api/services")&&!strcmp(method,"GET")) return h_services(c);
    if(!strcmp(url,"/api/service")&&is_post) return h_service_action(c,body);
    if(!strcmp(url,"/api/password")&&is_post) return h_password(c,body);

    return err_json(c,404,"not found");
}

int main(void){
    signal(SIGPIPE,SIG_IGN);
    /* memory: single malloc arena + aggressive trim (glibc only; musl no-op) */
#ifdef __GLIBC__
    mallopt(M_ARENA_MAX,1);
    mallopt(M_TRIM_THRESHOLD,128*1024);
    mallopt(M_TOP_PAD,32*1024);
#endif
    signal(SIGCHLD,SIG_DFL);
    chdir(BASE);
    load_or_init_config();
    load_sites();
    mkdir(EXTRADIR,0755);
    struct MHD_Daemon *d=MHD_start_daemon(
        MHD_USE_THREAD_PER_CONNECTION|MHD_USE_INTERNAL_POLLING_THREAD,
        PORT, NULL,NULL, ahc,NULL,
        MHD_OPTION_NOTIFY_COMPLETED, ci_free,NULL,
        MHD_OPTION_CONNECTION_TIMEOUT,(unsigned int)60,
        MHD_OPTION_CONNECTION_LIMIT,(unsigned int)32,
        MHD_OPTION_CONNECTION_MEMORY_LIMIT,(size_t)(32*1024),
        MHD_OPTION_THREAD_STACK_SIZE,(size_t)(192*1024),
        MHD_OPTION_END);
    if(!d){ fprintf(stderr,"failed to bind :%d\n",PORT); return 1; }
    printf("panel-c listening on 127.0.0.1:%d\n",PORT);
    fflush(stdout);
    pause();
    return 0;
}
