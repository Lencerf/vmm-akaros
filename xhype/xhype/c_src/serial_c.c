#include <termios.h>
#include <unistd.h>
#include <stdlib.h>

void make_stdin_raw_c() {
    struct termios old;
    tcgetattr(STDIN_FILENO, &old);
    struct termios new = old;
    cfmakeraw(&new);
    new.c_cflag |= CLOCAL;
    tcsetattr(STDIN_FILENO, TCSANOW, &new);
}

void cpu_memory_barrier_c() {
    __sync_synchronize();
}

unsigned char read_stdin_c() {
    unsigned char buff;
    if (read(STDIN_FILENO, &buff, 1) == 1) {
        return buff;
    } else {
        exit(1);
    }
}