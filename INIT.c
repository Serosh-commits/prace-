
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <seccomp.h>
#include <sqlite3.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <zmq.h>
#include <curl/curl.h>
#include <jansson.h>
#include <math.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <limits.h>
#include <pwd.h>

#if defined(__has_include)
# if __has_include(<openssl/sha.h>)
#  include <openssl/sha.h>
#  define HAVE_OPENSSL_SHA 1
# else
#  define HAVE_OPENSSL_SHA 0
# endif
#else
# include <openssl/sha.h>
# ifdef SHA256_DIGEST_LENGTH
#  define HAVE_OPENSSL_SHA 1
# else
#  define HAVE_OPENSSL_SHA 0
# endif
#endif

#if !HAVE_OPENSSL_SHA
# ifndef SHA256_DIGEST_LENGTH
#  define SHA256_DIGEST_LENGTH 32
# endif
#endif

#define MAX_PROCESSES 20
#define MAX_SYSCALLS 5000
#define NEURON_WEIGHTS 32
#define QUANTUM_QUBITS 8
#define MAX_ANOMALY_SCORE 100.0
#define ZMQ_PORT "5555"

static inline uint64_t rdtsc(void)
{
    unsigned int lo,hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi<<32)|lo;
}

typedef struct{
    pid_t pid;
    uint64_t syscall_count;
    double latency_avg;
    double latency_volatility;
    double anomaly_score;
    uint64_t quantum_state;
    uint64_t cpu_cycles;
    double energy_consumption;
    char cmdline[256];
    int active;
    time_t last_alert_time;
    int alerted;
}ProcessStats;

typedef struct{
    double weights[NEURON_WEIGHTS];
    double bias;
    double learning_rate;
}Perceptron;

typedef struct{
    ProcessStats stats[MAX_PROCESSES];
    int process_count;
    sqlite3 *db;
    char merkle_root[SHA256_DIGEST_LENGTH*2+1];
    void *zmq_context;
    void *zmq_socket;
    int bpf_fd;
    uint64_t system_memory_usage;
}MonitorState;

static MonitorState state;
static pthread_mutex_t state_mutex=PTHREAD_MUTEX_INITIALIZER;
static volatile int running=1;
static Perceptron perceptron;

static char *expand_path(const char *path)
{
    if(!path) return NULL;
    if(path[0]=='~'&&(path[1]=='/'||path[1]=='\0')){
        const char *home=getenv("HOME");
        if(!home){
            struct passwd *pw=getpwuid(getuid());
            if(pw&&pw->pw_dir) home=pw->pw_dir;
        }
        if(!home) home=".";
        size_t needed=strlen(home)+strlen(path)+1;
        char *out=malloc(needed);
        if(!out) return NULL;
        strcpy(out,home);
        strcat(out,path+1);
        return out;
    }else{
        return strdup(path);
    }
}

static char *default_db_path(void)
{
    const char *env=getenv("POLYMONITOR_DB");
    if(env&&env[0]!='\0') return expand_path(env);
    const char *home=getenv("HOME");
    if(!home) home=".";
    size_t plen=strlen(home)+strlen("/.polymonitor/polymonitor.db")+1;
    char *path=malloc(plen);
    if(!path) return NULL;
    snprintf(path,plen,"%s/.polymonitor/polymonitor.db",home);
    return path;
}

static void safe_copy_cmdline(const char *src,char *dst,size_t dstlen)
{
    if(!dst||dstlen==0) return;
    if(!src){ dst[0]='\0'; return; }
    size_t j=0;
    size_t n=strlen(src);
    for(size_t i=0;i<n&&j+1<dstlen;++i){
        char c=src[i];
        dst[j++]=(c=='\0')?' ':c;
    }
    dst[j<dstlen?j:dstlen-1]='\0';
}

void init_perceptron(Perceptron *p)
{
    if(!p) return;
    p->learning_rate=0.01;
    for(int i=0;i<NEURON_WEIGHTS;++i) p->weights[i]=((double)rand()/RAND_MAX)*0.1;
    p->bias=0.0;
}

double predict_syscall(Perceptron *p,uint64_t *history,int len)
{
    if(!p||!history||len<=0) return 0.0;
    double sum=p->bias;
    for(int i=0;i<len&&i<NEURON_WEIGHTS;++i) sum+=p->weights[i]*(double)history[i];
    return fmax(0.0,sum);
}

void train_perceptron(Perceptron *p,uint64_t *history,int len,double target)
{
    if(!p||!history||len<=0) return;
    double pred=predict_syscall(p,history,len);
    double error=target-pred;
    for(int i=0;i<len&&i<NEURON_WEIGHTS;++i) p->weights[i]+=p->learning_rate*error*(double)history[i];
    p->bias+=p->learning_rate*error;
}

double compute_volatility(uint64_t *latencies,int len)
{
    if(!latencies||len<=0) return 0.0;
    double mean=0.0;
    double var=0.0;
    for(int i=0;i<len;++i) mean+=(double)latencies[i];
    mean/=len;
    for(int i=0;i<len;++i) var+=pow((double)latencies[i]-mean,2);
    return sqrt(var/len);
}

double compute_anomaly_score(double pred,double actual,double volatility,uint64_t samples)
{
    const uint64_t MIN_SAMPLES_FOR_ALERT=5;
    const double VOLATILITY_FLOOR=1.0;
    if(samples<MIN_SAMPLES_FOR_ALERT) return 0.0;
    double denom=(volatility<VOLATILITY_FLOOR)?VOLATILITY_FLOOR:volatility;
    double z_score=fabs(actual-pred)/denom;
    double scaled=z_score*10.0;
    return (scaled>MAX_ANOMALY_SCORE)?MAX_ANOMALY_SCORE:scaled;
}

void apply_dynamic_seccomp(pid_t pid,uint64_t syscall_count)
{
    scmp_filter_ctx ctx=seccomp_init(SCMP_ACT_KILL);
    if(!ctx) return;
    seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(read),0);
    seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(write),0);
    seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(exit),0);
    seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(exit_group),0);
    seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(rt_sigreturn),0);
    if(syscall_count>1000){
        seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(open),0);
        seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(openat),0);
    }
    seccomp_load(ctx);
    seccomp_release(ctx);
}

int init_bpf_tracing(void)
{
    state.bpf_fd=-1;
    return -1;
}

void log_stats(sqlite3 *db,ProcessStats *stats)
{
    if(!db||!stats) return;
    const char *sql=
        "INSERT INTO stats (pid, syscall_count, latency_avg, latency_volatility, anomaly_score, "
        "quantum_state, cpu_cycles, energy_consumption, cmdline) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt=NULL;
    if(sqlite3_prepare_v2(db,sql,-1,&stmt,NULL)!=SQLITE_OK){
        fprintf(stderr,"sqlite prepare failed: %s\n",sqlite3_errmsg(db));
        return;
    }
    sqlite3_bind_int(stmt,1,stats->pid);
    sqlite3_bind_int64(stmt,2,stats->syscall_count);
    sqlite3_bind_double(stmt,3,stats->latency_avg);
    sqlite3_bind_double(stmt,4,stats->latency_volatility);
    sqlite3_bind_double(stmt,5,stats->anomaly_score);
    sqlite3_bind_int64(stmt,6,stats->quantum_state);
    sqlite3_bind_int64(stmt,7,stats->cpu_cycles);
    sqlite3_bind_double(stmt,8,stats->energy_consumption);
    sqlite3_bind_text(stmt,9,stats->cmdline,-1,SQLITE_STATIC);
    if(sqlite3_step(stmt)!=SQLITE_DONE) fprintf(stderr,"sqlite step failed: %s\n",sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
}

void compute_merkle_root(MonitorState *st)
{
    if(!st) return;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char buf[4096];
    size_t off=0;
    for(int i=0;i<st->process_count;++i){
        off+=snprintf((char *)buf+off,sizeof(buf)-off,
                      "%d:%" PRIu64 ":%.6f:%.6f:%.6f:%" PRIu64 ":%" PRIu64 ":%.6f:%s;",
                      st->stats[i].pid,
                      st->stats[i].syscall_count,
                      st->stats[i].latency_avg,
                      st->stats[i].latency_volatility,
                      st->stats[i].anomaly_score,
                      st->stats[i].quantum_state,
                      st->stats[i].cpu_cycles,
                      st->stats[i].energy_consumption,
                      st->stats[i].cmdline);
        if(off>=sizeof(buf)-256) break;
    }
#if HAVE_OPENSSL_SHA
    SHA256(buf,off,hash);
#else
    memset(hash,0,sizeof(hash));
    for(size_t i=0;i<off;++i) hash[i%SHA256_DIGEST_LENGTH]^=buf[i];
#endif
    for(int i=0;i<SHA256_DIGEST_LENGTH;++i) snprintf(&st->merkle_root[i*2],3,"%02x",hash[i]);
    st->merkle_root[SHA256_DIGEST_LENGTH*2]='\0';
}

size_t custom_curl_write_callback(void *contents,size_t size,size_t nmemb,void *userp)
{
    (void)contents;
    (void)userp;
    return size*nmemb;
}

void send_alert(const char *message)
{
    if(!message) return;
    const char *webhook=getenv("POLYMONITOR_WEBHOOK");
    if(!webhook||webhook[0]=='\0') return;
    CURL *curl=curl_easy_init();
    if(!curl) return;
    json_t *obj=json_object();
    json_object_set_new(obj,"alert",json_string(message));
    char *json_str=json_dumps(obj,JSON_COMPACT);
    curl_easy_setopt(curl,CURLOPT_URL,webhook);
    curl_easy_setopt(curl,CURLOPT_POSTFIELDS,json_str);
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,custom_curl_write_callback);
    const char *insecure=getenv("POLYMONITOR_INSECURE");
    if(insecure&&insecure[0]=='1'){
        curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L);
        curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST,0L);
    }
    CURLcode rc=curl_easy_perform(curl);
    if(rc!=CURLE_OK) fprintf(stderr,"curl perform failed: %s\n",curl_easy_strerror(rc));
    curl_easy_cleanup(curl);
    json_decref(obj);
    free(json_str);
}

void get_cmdline(pid_t pid,char *cmdline,size_t len)
{
    if(!cmdline||len==0) return;
    char path[64];
    snprintf(path,sizeof(path),"/proc/%d/cmdline",pid);
    int fd=open(path,O_RDONLY);
    if(fd<0){
        snprintf(cmdline,len,"[pid:%d]",pid);
        return;
    }
    ssize_t r=read(fd,cmdline,len-1);
    if(r<=0) cmdline[0]='\0';
    else{
        size_t j=0;
        for(ssize_t i=0;i<r&&j+1<(ssize_t)len;++i){
            char c=cmdline[i];
            cmdline[j++]=(c=='\0')?' ':c;
        }
        cmdline[j<len?j:len-1]='\0';
    }
    close(fd);
}

uint64_t measure_cpu_cycles(pid_t pid)
{
    struct perf_event_attr pe;
    memset(&pe,0,sizeof(pe));
    pe.type=PERF_TYPE_HARDWARE;
    pe.size=sizeof(pe);
    pe.config=PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled=1;
    pe.exclude_kernel=1;
    int fd=syscall(__NR_perf_event_open,&pe,pid,-1,-1,0);
    if(fd<0) return 0;
    if(ioctl(fd,PERF_EVENT_IOC_RESET,0)==-1){ close(fd); return 0; }
    if(ioctl(fd,PERF_EVENT_IOC_ENABLE,0)==-1){ close(fd); return 0; }
    if(ioctl(fd,PERF_EVENT_IOC_DISABLE,0)==-1){ close(fd); return 0; }
    uint64_t cnt=0;
    if(read(fd,&cnt,sizeof(cnt))!=sizeof(cnt)) cnt=0;
    close(fd);
    return cnt;
}

double measure_energy(void)
{
    const char *path="/sys/class/powercap/intel-rapl:0/energy_uj";
    int fd=open(path,O_RDONLY);
    if(fd<0) return 0.0;
    char buf[64];
    ssize_t r=read(fd,buf,sizeof(buf)-1);
    close(fd);
    if(r<=0) return 0.0;
    buf[r]='\0';
    double uj=atof(buf);
    return (uj>0.0)?(uj/1e6):0.0;
}

uint64_t quantum_circuit_sim(int qubits)
{
    uint64_t qstate=0;
    for(int i=0;i<qubits;i++){
        double r=(double)rand()/RAND_MAX;
        qstate|=((r<0.5?0ULL:1ULL)<<i);
    }
    for(int i=0;i<qubits-1;i++) if(rand()%2) qstate^=(1ULL<<i)|(1ULL<<(i+1));
    return qstate;
}

typedef struct{ pid_t pid; int idx; Perceptron *p; }TraceArg;

void *trace_thread(void *arg)
{
    TraceArg *ta=(TraceArg *)arg;
    if(!ta) return NULL;
    pid_t pid=ta->pid;
    int idx=ta->idx;
    Perceptron *p=ta->p;
    int status=0;
    if(waitpid(pid,&status,0)==-1){
        fprintf(stderr,"waitpid initial for pid %d failed: %s\n",pid,strerror(errno));
        free(ta);
        return NULL;
    }
    if(WIFEXITED(status)||WIFSIGNALED(status)){
        pthread_mutex_lock(&state_mutex);
        state.stats[idx].active=0;
        pthread_mutex_unlock(&state_mutex);
        free(ta);
        return NULL;
    }
    ptrace(PTRACE_SETOPTIONS,pid,0,PTRACE_O_TRACESYSGOOD);
    char cmd[256]={0};
    get_cmdline(pid,cmd,sizeof(cmd));
    pthread_mutex_lock(&state_mutex);
    safe_copy_cmdline(cmd,state.stats[idx].cmdline,sizeof(state.stats[idx].cmdline));
    pthread_mutex_unlock(&state_mutex);
    uint64_t latencies[MAX_SYSCALLS]={0};
    int lat_count=0;
    uint64_t syscall_history[NEURON_WEIGHTS]={0};
    int syscall_idx=0;
    int in_syscall=0;
    uint64_t entry_tsc=0;
    while(running){
        if(ptrace(PTRACE_SYSCALL,pid,0,0)==-1){
            if(errno==ESRCH) break;
            fprintf(stderr,"ptrace SYSCALL failed for %d: %s\n",pid,strerror(errno));
            break;
        }
        if(waitpid(pid,&status,0)==-1){
            if(errno==EINTR) continue;
            break;
        }
        if(WIFEXITED(status)||WIFSIGNALED(status)){
            pthread_mutex_lock(&state_mutex);
            state.stats[idx].active=0;
            pthread_mutex_unlock(&state_mutex);
            break;
        }
        if(!WIFSTOPPED(status)) continue;
        int sig=WSTOPSIG(status);
        if(sig==(SIGTRAP|0x80)){
            if(!in_syscall){
                entry_tsc=rdtsc();
                in_syscall=1;
            }else{
                uint64_t now=rdtsc();
                uint64_t delta=(now>entry_tsc)?(now-entry_tsc):0;
                pthread_mutex_lock(&state_mutex);
                ProcessStats *st=&state.stats[idx];
                st->syscall_count++;
                if(lat_count<MAX_SYSCALLS) latencies[lat_count++]=delta;
                else{
                    memmove(latencies,latencies+1,(MAX_SYSCALLS-1)*sizeof(uint64_t));
                    latencies[MAX_SYSCALLS-1]=delta;
                }
                double prev_avg=st->latency_avg;
                st->latency_avg=((prev_avg*(st->syscall_count-1))+(double)delta)/st->syscall_count;
                st->latency_volatility=compute_volatility(latencies,lat_count);
                syscall_history[syscall_idx%NEURON_WEIGHTS]=st->syscall_count;
                double pred=predict_syscall(p,syscall_history,NEURON_WEIGHTS);
                st->anomaly_score=compute_anomaly_score(pred,(double)st->syscall_count,st->latency_volatility,st->syscall_count);
                double threshold=50.0;
                const char *th_env=getenv("POLYMONITOR_ALERT_THRESHOLD");
                if(th_env) threshold=atof(th_env);
                time_t nowt=time(NULL);
                const int ALERT_COOLDOWN=60;
                if(st->anomaly_score>=threshold&&st->syscall_count>=5){
                    if(!st->alerted||(nowt-st->last_alert_time)>=ALERT_COOLDOWN){
                        char alert[512];
                        snprintf(alert,sizeof(alert),"Anomaly detected: PID %d, Score %.1f, Cmd: %s",st->pid,st->anomaly_score,st->cmdline);
                        send_alert(alert);
                        st->alerted=1;
                        st->last_alert_time=nowt;
                    }
                }else{
                    st->alerted=0;
                }
                train_perceptron(p,syscall_history,NEURON_WEIGHTS,(double)st->syscall_count);
                st->quantum_state=quantum_circuit_sim(QUANTUM_QUBITS);
                st->cpu_cycles=measure_cpu_cycles(pid);
                st->energy_consumption=measure_energy();
                log_stats(state.db,st);
                compute_merkle_root(&state);
                struct sysinfo si;
                if(sysinfo(&si)==0) state.system_memory_usage=si.totalram-si.freeram;
                pthread_mutex_unlock(&state_mutex);
                syscall_idx++;
                in_syscall=0;
            }
        }else{
            if(ptrace(PTRACE_CONT,pid,0,sig)==-1){
                if(errno==ESRCH) break;
            }
        }
    }
    pthread_mutex_lock(&state_mutex);
    state.stats[idx].active=0;
    pthread_mutex_unlock(&state_mutex);
    free(ta);
    return NULL;
}

void signal_handler(int sig)
{
    (void)sig;
    running=0;
}

void *zmq_server(void *arg)
{
    (void)arg;
    void *socket=state.zmq_socket;
    if(!socket) return NULL;
    while(running){
        zmq_msg_t req;
        zmq_msg_init(&req);
        int rc=zmq_msg_recv(&req,socket,0);
        if(rc==-1){
            zmq_msg_close(&req);
            if(errno==EINTR) continue;
            break;
        }
        size_t size=zmq_msg_size(&req);
        char *buf=malloc(size+1);
        if(!buf){ zmq_msg_close(&req); break; }
        memcpy(buf,zmq_msg_data(&req),size);
        buf[size]='\0';
        json_t *root=json_loads(buf,0,NULL);
        if(root){
            json_t *cmd=json_object_get(root,"cmd");
            if(json_is_string(cmd)&&strcmp(json_string_value(cmd),"stats")==0){
                json_t *res=json_array();
                pthread_mutex_lock(&state_mutex);
                for(int i=0;i<state.process_count;++i){
                    if(!state.stats[i].active) continue;
                    json_t *s=json_object();
                    json_object_set_new(s,"pid",json_integer(state.stats[i].pid));
                    json_object_set_new(s,"syscall_count",json_integer(state.stats[i].syscall_count));
                    json_object_set_new(s,"latency_avg",json_real(state.stats[i].latency_avg));
                    json_object_set_new(s,"anomaly_score",json_real(state.stats[i].anomaly_score));
                    json_object_set_new(s,"cmdline",json_string(state.stats[i].cmdline));
                    json_array_append_new(res,s);
                }
                pthread_mutex_unlock(&state_mutex);
                char *out=json_dumps(res,JSON_COMPACT);
                zmq_send(socket,out,strlen(out),0);
                free(out);
                json_decref(res);
            }else{
                const char *resp="{\"error\":\"unknown cmd\"}";
                zmq_send(socket,resp,strlen(resp),0);
            }
            json_decref(root);
        }else{
            const char *resp="{\"error\":\"invalid json\"}";
            zmq_send(socket,resp,strlen(resp),0);
        }
        free(buf);
        zmq_msg_close(&req);
    }
    return NULL;
}

void *console_dashboard(void *arg)
{
    (void)arg;
    while(running){
        sleep(5);
        pthread_mutex_lock(&state_mutex);
        int active_count=0;
        for(int i=0;i<state.process_count;++i) if(state.stats[i].active) ++active_count;
        fprintf(stderr,"PolyMonitor: total slots=%d active=%d merkle=%s\n",state.process_count,active_count,state.merkle_root);
        for(int i=0;i<state.process_count;++i){
            if(!state.stats[i].active) continue;
            fprintf(stderr," PID %d: syscalls=%" PRIu64 " anomaly=%.1f cmd=%s\n",state.stats[i].pid,state.stats[i].syscall_count,state.stats[i].anomaly_score,state.stats[i].cmdline);
        }
        pthread_mutex_unlock(&state_mutex);
    }
    return NULL;
}

int main(int argc,char *argv[])
{
    if(argc<2){
        fprintf(stderr,"Usage: %s <binary> [binary...]\n",argv[0]);
        return 1;
    }
    signal(SIGINT,signal_handler);
    signal(SIGTERM,signal_handler);
    srand((unsigned)time(NULL)^(unsigned)getpid());
    memset(&state,0,sizeof(state));
    init_perceptron(&perceptron);
    char *dbpath=default_db_path();
    if(!dbpath){ fprintf(stderr,"Failed to determine DB path\n"); return 1; }
    char dbdir[PATH_MAX];
    strncpy(dbdir,dbpath,sizeof(dbdir));
    char *slash=strrchr(dbdir,'/');
    if(slash){
        *slash='\0';
        if(mkdir(dbdir,0700)==-1&&errno!=EEXIST) fprintf(stderr,"Warning: could not create DB dir %s: %s\n",dbdir,strerror(errno));
    }
    int flags=SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_FULLMUTEX;
    if(sqlite3_open_v2(dbpath,&state.db,flags,NULL)!=SQLITE_OK){
        fprintf(stderr,"Failed to open sqlite DB '%s': %s\n",dbpath,sqlite3_errmsg(state.db));
        if(state.db) sqlite3_close(state.db);
        state.db=NULL;
        if(sqlite3_open(":memory:",&state.db)!=SQLITE_OK){
            fprintf(stderr,"Failed to open in-memory DB: %s\n",sqlite3_errmsg(state.db));
            free(dbpath);
            return 1;
        }else{
            fprintf(stderr,"Using in-memory DB as fallback\n");
        }
    }
    free(dbpath);
    const char *schema=
        "CREATE TABLE IF NOT EXISTS stats ("
        "pid INTEGER, syscall_count INTEGER, latency_avg REAL, latency_volatility REAL, "
        "anomaly_score REAL, quantum_state INTEGER, cpu_cycles INTEGER, energy_consumption REAL, cmdline TEXT);";
    char *errmsg=NULL;
    if(sqlite3_exec(state.db,schema,NULL,NULL,&errmsg)!=SQLITE_OK){
        fprintf(stderr,"Failed to create table: %s\n",errmsg?errmsg:"unknown");
        if(errmsg) sqlite3_free(errmsg);
    }
    state.zmq_context=zmq_ctx_new();
    if(!state.zmq_context) fprintf(stderr,"Failed to create zmq context\n");
    else{
        state.zmq_socket=zmq_socket(state.zmq_context,ZMQ_REP);
        if(!state.zmq_socket){
            fprintf(stderr,"Failed to create zmq socket\n");
            zmq_ctx_destroy(state.zmq_context);
            state.zmq_context=NULL;
        }else{
            char bind_addr[64];
            snprintf(bind_addr,sizeof(bind_addr),"tcp://*:%s",ZMQ_PORT);
            if(zmq_bind(state.zmq_socket,bind_addr)!=0){
                fprintf(stderr,"Failed to bind zmq socket: %s\n",zmq_strerror(errno));
                zmq_close(state.zmq_socket);
                zmq_ctx_destroy(state.zmq_context);
                state.zmq_socket=NULL;
                state.zmq_context=NULL;
            }
        }
    }
    pthread_t zmq_thread=0;
    if(state.zmq_socket){
        if(pthread_create(&zmq_thread,NULL,zmq_server,NULL)!=0){
            fprintf(stderr,"Failed to create zmq server thread\n");
            zmq_close(state.zmq_socket);
            zmq_ctx_destroy(state.zmq_context);
            state.zmq_socket=NULL;
            state.zmq_context=NULL;
        }
    }
    if(init_bpf_tracing()<0) fprintf(stderr,"eBPF tracing not initialized (not used in this build)\n");
    pthread_t dash_thread=0;
    if(pthread_create(&dash_thread,NULL,console_dashboard,NULL)!=0) fprintf(stderr,"Failed to create dashboard thread\n");
    for(int i=1;i<argc&&state.process_count<MAX_PROCESSES;++i){
        pid_t pid=fork();
        if(pid==-1){
            fprintf(stderr,"fork failed for %s: %s\n",argv[i],strerror(errno));
            continue;
        }
        if(pid==0){
            apply_dynamic_seccomp(getpid(),0);
            if(ptrace(PTRACE_TRACEME,0,NULL,NULL)==-1){}
            execvp(argv[i],&argv[i]);
            fprintf(stderr,"execvp failed for %s: %s\n",argv[i],strerror(errno));
            _exit(127);
        }else{
            pthread_mutex_lock(&state_mutex);
            int idx=state.process_count;
            state.stats[idx].pid=pid;
            state.stats[idx].syscall_count=0;
            state.stats[idx].latency_avg=0.0;
            state.stats[idx].latency_volatility=0.0;
            state.stats[idx].anomaly_score=0.0;
            state.stats[idx].quantum_state=0;
            state.stats[idx].cpu_cycles=0;
            state.stats[idx].energy_consumption=0.0;
            state.stats[idx].cmdline[0]='\0';
            state.stats[idx].active=1;
            state.stats[idx].last_alert_time=0;
            state.stats[idx].alerted=0;
            state.process_count++;
            pthread_mutex_unlock(&state_mutex);
            TraceArg *ta=malloc(sizeof(TraceArg));
            if(!ta){ fprintf(stderr,"malloc failed for trace arg\n"); continue; }
            ta->pid=pid;
            ta->idx=idx;
            ta->p=&perceptron;
            pthread_t thr;
            if(pthread_create(&thr,NULL,trace_thread,ta)!=0){
                fprintf(stderr,"Failed to create trace thread for pid %d\n",pid);
                free(ta);
                continue;
            }
            pthread_detach(thr);
        }
    }
    while(running) sleep(1);
    running=0;
    sleep(1);
    if(state.zmq_socket){ zmq_close(state.zmq_socket); state.zmq_socket=NULL; }
    if(state.zmq_context){ zmq_ctx_destroy(state.zmq_context); state.zmq_context=NULL; }
    if(zmq_thread) pthread_join(zmq_thread,NULL);
    json_t *root=json_object();
    json_object_set_new(root,"merkle_root",json_string(state.merkle_root));
    json_object_set_new(root,"process_count",json_integer(state.process_count));
    json_t *procs=json_array();
    for(int i=0;i<state.process_count;++i){
        json_t *p=json_object();
        json_object_set_new(p,"pid",json_integer(state.stats[i].pid));
        json_object_set_new(p,"cmdline",json_string(state.stats[i].cmdline));
        json_object_set_new(p,"syscall_count",json_integer(state.stats[i].syscall_count));
        json_array_append_new(procs,p);
    }
    json_object_set_new(root,"processes",procs);
    char *out=json_dumps(root,JSON_INDENT(2));
    FILE *f=fopen("polymonitor.json","w");
    if(f){ fprintf(f,"%s\n",out); fclose(f); }
    else fprintf(stderr,"Failed to write polymonitor.json\n");
    free(out);
    json_decref(root);
    if(state.db) sqlite3_close(state.db);
    pthread_cancel(dash_thread);
    pthread_join(dash_thread,NULL);
    return 0;
}
