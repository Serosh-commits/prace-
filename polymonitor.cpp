#include <ncurses.h>
#include <locale.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <seccomp.h>
#include <sqlite3.h>
#include <pthread.h>
#include <zmq.h>
#include <curl/curl.h>
#include <jansson.h>
#include <openssl/sha.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <pwd.h>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <ctime>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>

#define MAX_PROCS      20
#define MAX_SYSCALLS   5000
#define NEURON_WEIGHTS 32
#define ZMQ_PORT       "5555"
#define ALERT_COOLDOWN 60

static std::string commas(uint64_t val) {
    std::stringstream ss;
    ss.imbue(std::locale(""));
    ss << val;
    return ss.str();
}
static std::string dcommas(double val, int prec = 1) {
    std::stringstream ss;
    ss.imbue(std::locale(""));
    ss << std::fixed << std::setprecision(prec) << val;
    return ss.str();
}

struct ProcessStats {
    pid_t   pid{};
    uint64_t syscalls{};
    double  lat_avg{};
    double  lat_vol{};
    double  anomaly{};
    uint64_t cpu_cycles{};
    double  energy{};
    std::string cmdline;
    bool    active{false};
    time_t  last_alert{};
    bool    alerted{false};
    std::chrono::steady_clock::time_point last_alert_tp;
};

struct Perceptron {
    double w[NEURON_WEIGHTS]{};
    double bias{};
    double lr{0.01};
};

struct Monitor {
    std::vector<ProcessStats> procs;
    pthread_mutex_t mtx;
    sqlite3* db{};
    std::string merkle;
    uint64_t mem_used{};
    double load[3]{};
    time_t uptime{};
    void* zmq_ctx{};
    void* zmq_sock{};
    std::atomic<bool> run{true};
    Perceptron perceptron{};
    std::string last_alert_msg;
    int cooldown_left{0};
};
static Monitor g;

static inline uint64_t rdtsc() {
    unsigned lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
static std::string expand_path(const std::string& p) {
    if (p.empty() || p[0] != '~') return p;
    const char* home = getenv("HOME");
    if (!home) { struct passwd* pw = getpwuid(getuid()); if (pw) home = pw->pw_dir; }
    if (!home) home = ".";
    return std::string(home) + p.substr(1);
}
static std::string db_path() {
    const char* env = getenv("POLYMONITOR_DB");
    std::string path = env && env[0] ? expand_path(env) : expand_path("~/.polymonitor/polymonitor.db");
    size_t s = path.find_last_of('/');
    if (s != std::string::npos) {
        std::string dir = path.substr(0, s);
        mkdir(dir.c_str(), 0700);
    }
    return path;
}

static void init_perceptron(Perceptron* p) {
    for (int i = 0; i < NEURON_WEIGHTS; ++i)
        p->w[i] = ((double)rand() / RAND_MAX) * 0.1 - 0.05;
    p->bias = 0.0;
}
static double predict(const Perceptron* p, const uint64_t* hist, int len) {
    double sum = p->bias;
    for (int i = 0; i < len && i < NEURON_WEIGHTS; ++i)
        sum += p->w[i] * (double)hist[i];
    return std::max(0.0, sum);
}
static void train(Perceptron* p, const uint64_t* hist, int len, double target) {
    double pred = predict(p, hist, len);
    double err  = target - pred;
    for (int i = 0; i < len && i < NEURON_WEIGHTS; ++i) {
        p->w[i] += p->lr * err * (double)hist[i];
        if (p->w[i] < -10.0) p->w[i] = -10.0;
        if (p->w[i] >  10.0) p->w[i] = 10.0;
    }
    p->bias += p->lr * err;
    if (p->bias < -10.0) p->bias = -10.0;
    if (p->bias >  10.0) p->bias = 10.0;
}

static void log_stats(const ProcessStats& s) {
    pthread_mutex_lock(&g.mtx);
    if (!g.db) { pthread_mutex_unlock(&g.mtx); return; }
    const char* sql = "INSERT INTO stats(pid,syscall_count,latency_avg,latency_volatility,"
        "anomaly_score,cpu_cycles,energy_consumption,cmdline) VALUES(?,?,?,?,?,?,?,?);";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(g.db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&g.mtx); return;
    }
    sqlite3_bind_int   (stmt,1,s.pid);
    sqlite3_bind_int64 (stmt,2,s.syscalls);
    sqlite3_bind_double(stmt,3,s.lat_avg);
    sqlite3_bind_double(stmt,4,s.lat_vol);
    sqlite3_bind_double(stmt,5,s.anomaly);
    sqlite3_bind_int64 (stmt,6,s.cpu_cycles);
    sqlite3_bind_double(stmt,7,s.energy);
    std::string cmd_trunc = s.cmdline.size() > 30 ? s.cmdline.substr(0,27) + "..." : s.cmdline;
    sqlite3_bind_text  (stmt,8,cmd_trunc.c_str(),-1,SQLITE_TRANSIENT);
    int step_rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g.mtx);
}

static void compute_merkle() {
    pthread_mutex_lock(&g.mtx);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    std::string buf;
    for (const auto& p : g.procs) {
        if (!p.active) continue;
        char line[512];
        snprintf(line, sizeof(line),
            "%d:%" PRIu64 ":%.2f:%.2f:%.2f:%" PRIu64 ":%.2f:%s;",
            p.pid, p.syscalls, p.lat_avg, p.lat_vol, p.anomaly, p.cpu_cycles, p.energy, p.cmdline.c_str());
        buf += line;
    }
    SHA256((const unsigned char*)buf.data(), buf.size(), hash);
    char hex[65]{};
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        snprintf(hex + i * 2, 3, "%02x", hash[i]);
    g.merkle = hex;
    pthread_mutex_unlock(&g.mtx);
}

static void send_alert(const std::string& msg) {
    const char* hook = getenv("POLYMONITOR_WEBHOOK");
    if (!hook || !hook[0]) return;
    CURL* c = curl_easy_init();
    if (!c) return;
    json_t* root = json_object();
    if (!root) { curl_easy_cleanup(c); return; }
    json_object_set_new(root, "content", json_string(msg.c_str()));
    char* txt = json_dumps(root, JSON_COMPACT);
    if (txt) {
        curl_easy_setopt(c, CURLOPT_URL, hook);
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, txt);
        curl_easy_perform(c);
        free(txt);
    }
    curl_easy_cleanup(c);
    json_decref(root);
}

static std::string get_cmdline(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return "[unknown]";
    char buf[256]{};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return "[unknown]";
    for (ssize_t i = 0; i < n; ++i) if (buf[i] == '\0') buf[i] = ' ';
    std::string ret(buf, n);
    if (ret.size() > 30) ret = ret.substr(0, 27) + "...";
    return ret;
}

static uint64_t perf_cycles(pid_t pid) {
    struct perf_event_attr pe{};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    int fd = syscall(__NR_perf_event_open, &pe, pid, -1, -1, 0);
    if (fd < 0) return 0;
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    usleep(1000);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    uint64_t val = 0;
    read(fd, &val, sizeof(val));
    close(fd);
    return val;
}
static double rapl_energy() {
    const char* p = "/sys/class/powercap/intel-rapl:0/energy_uj";
    int fd = open(p, O_RDONLY);
    if (fd < 0) return 0.0;
    char buf[32]{};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0.0;
    buf[n] = '\0';
    return std::strtod(buf, nullptr) / 1e6;
}

static void* trace_thread(void* arg) {
    pid_t pid = *(pid_t*)arg;
    free(arg);
    int status;
    if (waitpid(pid, &status, 0) == -1) return nullptr;
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) == -1) {
    }

    std::string cmd = get_cmdline(pid);
    int idx = -1;
    pthread_mutex_lock(&g.mtx);
    for (int i = 0; i < MAX_PROCS; ++i) {
        if (i >= (int)g.procs.size()) break;
        if (!g.procs[i].active) { idx = i; break; }
    }
    if (idx == -1) {
        for (int i = 0; i < MAX_PROCS; ++i) {
            if (i >= (int)g.procs.size()) { g.procs.resize(i+1); }
            if (!g.procs[i].active) { idx = i; break; }
        }
    }
    if (idx == -1) { pthread_mutex_unlock(&g.mtx); return nullptr; }
    g.procs[idx] = { pid,0,0,0,0,0,0,cmd,true,0,false,std::chrono::steady_clock::now() };
    pthread_mutex_unlock(&g.mtx);

    std::vector<uint64_t> lat_buf;
    lat_buf.reserve(1024);
    uint64_t hist[NEURON_WEIGHTS] = {0};
    int hist_idx = 0;
    bool in_sys = false;
    uint64_t entry_tsc = 0;

    while (g.run) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) break;
        if (waitpid(pid, &status, 0) == -1) break;
        if (WIFEXITED(status) || WIFSIGNALED(status)) break;
        int sig = WSTOPSIG(status);

        if (sig == (SIGTRAP | 0x80)) {
            if (!in_sys) { entry_tsc = rdtsc(); in_sys = true; }
            else {
                uint64_t now_tsc = rdtsc();
                uint64_t delta = now_tsc > entry_tsc ? now_tsc - entry_tsc : 0;

                pthread_mutex_lock(&g.mtx);
                auto& s = g.procs[idx];
                s.syscalls++;
                if (lat_buf.size() < (size_t)MAX_SYSCALLS) lat_buf.push_back(delta);
                else { std::rotate(lat_buf.begin(), lat_buf.begin()+1, lat_buf.end()); lat_buf.back() = delta; }

                double prev = s.lat_avg;
                if (s.syscalls > 0) s.lat_avg = ((prev * (s.syscalls - 1)) + (double)delta) / (double)s.syscalls;

                double mean = 0.0;
                if (!lat_buf.empty()) {
                    for (auto v : lat_buf) mean += (double)v;
                    mean /= (double)lat_buf.size();
                    double var = 0.0;
                    for (auto v : lat_buf) var += ( (double)v - mean ) * ( (double)v - mean );
                    s.lat_vol = sqrt(var / (double)lat_buf.size());
                } else s.lat_vol = 0.0;

                hist[hist_idx++ % NEURON_WEIGHTS] = s.syscalls;
                double pred = predict(&g.perceptron, hist, NEURON_WEIGHTS);
                double vol = s.lat_vol < 1.0 ? 1.0 : s.lat_vol;
                double z = fabs((double)s.syscalls - pred) / vol;
                s.anomaly = std::min(z * 10.0, 100.0);

                double thresh = 50.0;
                const char* e = getenv("POLYMONITOR_ALERT_THRESHOLD");
                if (e) thresh = std::strtod(e, nullptr);
                time_t now_time = time(nullptr);
                auto now_tp = std::chrono::steady_clock::now();
                if (s.anomaly >= thresh && s.syscalls >= 5 &&
                    (!s.alerted || std::chrono::duration_cast<std::chrono::seconds>(now_tp - s.last_alert_tp).count() >= ALERT_COOLDOWN)) {
                    char msg[256];
                    snprintf(msg, sizeof(msg),
                        "Anomaly PID %d score %.1f cmd %s",
                        s.pid, s.anomaly, s.cmdline.c_str());
                    send_alert(msg);
                    g.last_alert_msg = msg;
                    s.alerted = true;
                    s.last_alert = now_time;
                    s.last_alert_tp = now_tp;
                    g.cooldown_left = ALERT_COOLDOWN;
                } else {
                    if (s.alerted) {
                        if (std::chrono::duration_cast<std::chrono::seconds>(now_tp - s.last_alert_tp).count() >= ALERT_COOLDOWN) s.alerted = false;
                    }
                }

                train(&g.perceptron, hist, NEURON_WEIGHTS, (double)s.syscalls);
                s.cpu_cycles = perf_cycles(pid);
                s.energy = rapl_energy();
                log_stats(s);
                compute_merkle();

                struct sysinfo si;
                if (sysinfo(&si) == 0) {
                    g.mem_used = (uint64_t)(si.totalram - si.freeram);
                    g.uptime = si.uptime;
                }
                getloadavg(g.load, 3);
                pthread_mutex_unlock(&g.mtx);
                in_sys = false;
            }
        }
        else {
            ptrace(PTRACE_CONT, pid, 0, sig);
        }
    }
    pthread_mutex_lock(&g.mtx);
    if (idx >= 0 && idx < (int)g.procs.size()) g.procs[idx].active = false;
    pthread_mutex_unlock(&g.mtx);
    return nullptr;
}

static void* zmq_thread(void*) {
    g.zmq_ctx = zmq_ctx_new();
    if (!g.zmq_ctx) return nullptr;
    g.zmq_sock = zmq_socket(g.zmq_ctx, ZMQ_REP);
    if (!g.zmq_sock) { zmq_ctx_destroy(g.zmq_ctx); g.zmq_ctx = nullptr; return nullptr; }
    int rcvto = 1000;
    zmq_setsockopt(g.zmq_sock, ZMQ_RCVTIMEO, &rcvto, sizeof(rcvto));

    std::string addr = std::string("tcp://*") + ":" + std::string(ZMQ_PORT);
    if (zmq_bind(g.zmq_sock, addr.c_str()) != 0) {
        zmq_close(g.zmq_sock);
        zmq_ctx_destroy(g.zmq_ctx);
        g.zmq_sock = nullptr; g.zmq_ctx = nullptr;
        return nullptr;
    }

    while (g.run) {
        zmq_msg_t req;
        zmq_msg_init(&req);
        int recv_rc = zmq_msg_recv(&req, g.zmq_sock, 0);
        if (recv_rc == -1) {
            zmq_msg_close(&req);
            if (!g.run) break;
            if (errno == EINTR) continue;
            continue;
        }
        size_t sz = zmq_msg_size(&req);
        std::string data((char*)zmq_msg_data(&req), sz);
        zmq_msg_close(&req);

        json_error_t err;
        json_t* root = json_loads(data.c_str(), 0, &err);
        json_t* resp = json_object();
        if (root && json_is_object(root)) {
            json_t* cmd = json_object_get(root, "cmd");
            if (cmd && json_is_string(cmd) && strcmp(json_string_value(cmd), "stats") == 0) {
                json_t* arr = json_array();
                pthread_mutex_lock(&g.mtx);
                for (const auto& p : g.procs) {
                    if (!p.active) continue;
                    json_t* o = json_object();
                    json_object_set_new(o, "pid", json_integer(p.pid));
                    json_object_set_new(o, "syscall_count", json_integer((json_int_t)p.syscalls));
                    json_object_set_new(o, "latency_avg", json_real(p.lat_avg));
                    json_object_set_new(o, "anomaly_score", json_real(p.anomaly));
                    json_object_set_new(o, "cmdline", json_string(p.cmdline.c_str()));
                    json_array_append_new(arr, o);
                }
                pthread_mutex_unlock(&g.mtx);
                json_object_set_new(resp, "stats", arr);
            }
            else {
                json_object_set_new(resp, "error", json_string("unknown cmd"));
            }
        }
        else {
            json_object_set_new(resp, "error", json_string("invalid json"));
        }
        if (root) json_decref(root);

        char* txt = json_dumps(resp, JSON_COMPACT);
        if (txt) zmq_send(g.zmq_sock, txt, strlen(txt), 0);
        free(txt);
        json_decref(resp);
    }
    if (g.zmq_sock) zmq_close(g.zmq_sock);
    if (g.zmq_ctx) zmq_ctx_destroy(g.zmq_ctx);
    g.zmq_sock = nullptr; g.zmq_ctx = nullptr;
    return nullptr;
}

static WINDOW* win_table{};
static WINDOW* win_status{};
static int selected_row = 0;
static int table_start = 0;
static int maxy, maxx;

static void draw_table() {
    werase(win_table);
    box(win_table, 0, 0);
    wattron(win_table, COLOR_PAIR(4) | A_BOLD);
    mvwprintw(win_table, 0, 2, " LDE PolyMonitor v1.0 ── q:quit r:refresh ↑↓:navigate Enter:detail ");
    wattroff(win_table, COLOR_PAIR(4) | A_BOLD);
    wattron(win_table, COLOR_PAIR(4) | A_BOLD);
    mvwprintw(win_table, 1, 1, " PID         │ CMDLINE                 │ SYSCALLS │ LATENCY │ ANOMALY │ CPU CYCLES   ");
    wattroff(win_table, COLOR_PAIR(4) | A_BOLD);

    pthread_mutex_lock(&g.mtx);
    int rows, cols;
    getmaxyx(win_table, rows, cols);
    int max_vis = rows - 4;

    int active_cnt = 0;
    for (auto& p : g.procs) if (p.active) ++active_cnt;
    if (selected_row >= active_cnt) selected_row = std::max(0, active_cnt - 1);
    if (table_start > selected_row) table_start = selected_row;
    if (table_start < selected_row - max_vis + 1) table_start = selected_row - max_vis + 1;
    if (table_start < 0) table_start = 0;

    int drawn = 0, vis_idx = 0;
    for (size_t i = 0; i < g.procs.size() && drawn < max_vis; ++i) {
        auto& p = g.procs[i];
        if (!p.active) continue;
        if (vis_idx++ < table_start) continue;

        int color = (p.anomaly >= 70) ? 3 :
            (p.anomaly >= 40) ? 2 : 1;
        if (vis_idx - 1 == selected_row) wattron(win_table, A_REVERSE);
        wattron(win_table, COLOR_PAIR(color));
        std::string cmd = p.cmdline.size() > 22 ? p.cmdline.substr(0, 19) + "..." : p.cmdline;

        char line[256];
        snprintf(line, sizeof(line),
            " %-10d │ %-22s │ %8s │ %7s │ %7s │ %13s ",
            p.pid, cmd.c_str(), commas(p.syscalls).c_str(),
            dcommas(p.lat_avg).c_str(), dcommas(p.anomaly).c_str(),
            commas(p.cpu_cycles).c_str());
        mvwprintw(win_table, drawn + 2, 1, "%s", line);

        if (p.anomaly >= 70) wattron(win_table, A_BLINK | COLOR_PAIR(3));
        wattroff(win_table, COLOR_PAIR(color));
        if (p.anomaly >= 70) wattroff(win_table, A_BLINK | COLOR_PAIR(3));
        if (vis_idx - 1 == selected_row) wattroff(win_table, A_REVERSE);
        ++drawn;
    }
    pthread_mutex_unlock(&g.mtx);
    wrefresh(win_table);
}

static void draw_status() {
    werase(win_status);
    box(win_status, 0, 0);
    pthread_mutex_lock(&g.mtx);
    char mem[64], load[64], up[64], cooldown[64], alert[128];
    uint64_t total_mem = (uint64_t)sysconf(_SC_PAGESIZE) * (uint64_t)sysconf(_SC_PHYS_PAGES);
    double mem_gb = (double)g.mem_used / 1e9, total_gb = (double)total_mem / 1e9;
    int pct = total_mem ? (int)(100.0 * (double)g.mem_used / (double)total_mem) : 0;
    snprintf(mem, sizeof(mem), "Memory: %.2f/%.2f GB (%d%%)", mem_gb, total_gb, pct);
    snprintf(load, sizeof(load), "Load: %.2f %.2f %.2f", g.load[0], g.load[1], g.load[2]);
    int days = (int)(g.uptime / 86400), h = (g.uptime % 86400) / 3600, m = (g.uptime % 3600) / 60;
    snprintf(up, sizeof(up), "Uptime: %dd %dh%dm", days, h, m);

    snprintf(cooldown, sizeof(cooldown), "Cooldown: %ds", g.cooldown_left);
    snprintf(alert, sizeof(alert), "High anomaly %s", g.last_alert_msg.c_str());

    mvwprintw(win_status, 1, 2, "MERKLE ROOT: %.64s", g.merkle.c_str());
    mvwprintw(win_status, 2, 2, "SYSTEM:  %s  %s  %s", mem, load, up);
    mvwprintw(win_status, 3, 2, "ALERTS:  %s │ %s", alert, cooldown);

    pthread_mutex_unlock(&g.mtx);
    wrefresh(win_status);
}

static void resize_handler(int) {
    endwin();
    refresh();
    clear();
    getmaxyx(stdscr, maxy, maxx);
    if (win_table) delwin(win_table);
    if (win_status) delwin(win_status);
    win_table = newwin(maxy - 5, maxx, 0, 0);
    win_status = newwin(5, maxx, maxy - 5, 0);
    draw_table();
    draw_status();
}

static void* ui_thread(void*) {
    setlocale(LC_ALL, "");
    initscr(); cbreak(); noecho(); keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE); curs_set(0);
    start_color();
    init_pair(1, COLOR_GREEN, COLOR_BLACK);
    init_pair(2, COLOR_YELLOW, COLOR_BLACK);
    init_pair(3, COLOR_RED, COLOR_BLACK);
    init_pair(4, COLOR_CYAN, COLOR_BLACK);

    getmaxyx(stdscr, maxy, maxx);
    win_table = newwin(maxy - 5, maxx, 0, 0);
    win_status = newwin(5, maxx, maxy - 5, 0);

    signal(SIGWINCH, resize_handler);

    int last_second = time(nullptr);

    while (g.run) {
        draw_table();
        draw_status();

        int ch = getch();
        if (ch == 'q') g.run = false;
        else if (ch == 'r') { }
        else if (ch == KEY_UP)   { if (selected_row > 0) --selected_row; }
        else if (ch == KEY_DOWN) {
            int cnt = 0;
            pthread_mutex_lock(&g.mtx);
            for (auto& p : g.procs) if (p.active) ++cnt;
            pthread_mutex_unlock(&g.mtx);
            if (selected_row < cnt - 1) ++selected_row;
        }
        else if (ch == 10) {
        }
        int cur_second = time(nullptr);
        if (cur_second != last_second && g.cooldown_left > 0) {
            g.cooldown_left--;
            last_second = cur_second;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    endwin();
    return nullptr;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cmd> [args...]\n", argv[0]);
        return 1;
    }
    srand((unsigned)time(nullptr));

    if (pthread_mutex_init(&g.mtx, nullptr) != 0) {
        fprintf(stderr, "Failed to init mutex\n");
        return 1;
    }

    std::string dbp = db_path();
    if (sqlite3_open(dbp.c_str(), &g.db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open DB: %s\n", sqlite3_errmsg(g.db));
        sqlite3_close(g.db);
        pthread_mutex_destroy(&g.mtx);
        return 1;
    }
    const char* schema = "CREATE TABLE IF NOT EXISTS stats("
        "pid INTEGER, syscall_count INTEGER, latency_avg REAL,"
        "latency_volatility REAL, anomaly_score REAL, cpu_cycles INTEGER,"
        "energy_consumption REAL, cmdline TEXT);";
    sqlite3_exec(g.db, schema, nullptr, nullptr, nullptr);

    init_perceptron(&g.perceptron);
    g.procs.resize(MAX_PROCS);

    struct sigaction sa{};
    sa.sa_handler = [](int){ g.run = false; };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    pthread_t zmq_thread_handle;
    pthread_create(&zmq_thread_handle, nullptr, zmq_thread, nullptr);

    pthread_t ui_thread_handle;
    pthread_create(&ui_thread_handle, nullptr, ui_thread, nullptr);

    for (int i = 1; i < argc && i < MAX_PROCS + 1; ++i) {
        pid_t pid = fork();
        if (pid == 0) {
            scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
            if (!ctx) _exit(127);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);

            seccomp_load(ctx);
            seccomp_release(ctx);

            ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
            execvp(argv[i], &argv[i]);
            _exit(127);
        }
        else if (pid > 0) {
            pid_t* pp = (pid_t*)malloc(sizeof(pid_t));
            *pp = pid;
            pthread_t tr;
            if (pthread_create(&tr, nullptr, trace_thread, pp) != 0) {
                free(pp);
            } else {
                pthread_detach(tr);
            }
        }
    }

    while (g.run) std::this_thread::sleep_for(std::chrono::milliseconds(200));
    g.run = false;
    pthread_join(ui_thread_handle, nullptr);
    pthread_join(zmq_thread_handle, nullptr);
    if (g.db) sqlite3_close(g.db);
    pthread_mutex_destroy(&g.mtx);
    return 0;
}
