#include <execinfo.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

static const char *out_path = "/tmp/hb/cstack.txt";

void level1(void) {
    void *bt[16];
    int n = backtrace(bt, 16);
    FILE *f = fopen(out_path, "w");
    backtrace_symbols_fd(bt, n, fileno(f));
    fclose(f);
    pthread_mutex_lock(&m);
}
void level2(void) { level1(); }
void level3(void) { level2(); }

void *worker(void *arg) {
    (void)arg;
    level3();
    return NULL;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        out_path = argv[1];
    }
    pthread_mutex_lock(&m);
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    usleep(300000);
    printf("READY %d\n", getpid());
    fflush(stdout);
    for (;;) {
        sleep(3600);
    }
}
