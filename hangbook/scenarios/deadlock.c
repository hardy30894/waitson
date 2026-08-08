#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static pthread_mutex_t a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t b = PTHREAD_MUTEX_INITIALIZER;

static void *other(void *arg) {
    (void)arg;
    pthread_mutex_lock(&b);
    usleep(300000);
    pthread_mutex_lock(&a);
    return NULL;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, other, NULL);
    pthread_mutex_lock(&a);
    usleep(300000);
    printf("READY %d\n", getpid());
    fflush(stdout);
    pthread_mutex_lock(&b);
    return 0;
}
