#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

static void *worker(void *arg) {
    (void)arg;
    pthread_mutex_lock(&m);
    for (;;) {
    }
    return NULL;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    usleep(200000);
    printf("READY %d\n", getpid());
    fflush(stdout);
    pthread_mutex_lock(&m);
    return 0;
}
