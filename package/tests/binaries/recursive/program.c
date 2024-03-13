#include <stdio.h>
#include <string.h>
#include <unistd.h>

void child_func(char *buf, int count) {
    recursive_child_resolve(buf, --count);
}

void recursive_child_resolve(char *buf, int count) {
    if (count > 0) {
        child_func(buf, count);
    } else {
        system(buf);
    }
}

void recursive_self_resolve(char *buf, int count) {
    if (count > 0) {
        recursive_self_resolve(buf, --count);
    } else {
        system(buf);
    }
}

void main(int argc, char **argv) {
    char buf[0x64] = {"ls -la"};
    recursive_self_resolve(buf, 10);
    recursive_child_resolve(argv[1], 10);
}