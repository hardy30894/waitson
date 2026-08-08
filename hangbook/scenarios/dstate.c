#include <stdio.h>
#include <unistd.h>

/* vfork parent sits in uninterruptible sleep (D, wchan vfork_done)
   until the child execs or exits; the child deliberately does neither. */
int main(void) {
    printf("READY %d\n", getpid());
    fflush(stdout);
    pid_t p = vfork();
    if (p == 0) {
        for (;;)
            pause();
    }
    return 0;
}
