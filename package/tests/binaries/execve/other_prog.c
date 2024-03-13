#include <stdio.h>
#include <stdlib.h>

void main(int argc, char **argv) {
    char cmd[0x40];
    printf("%s Running: %s %s\n", argv[0], argv[1], argv[2]);
    snprintf(cmd, 0x40, "echo '%s %s'", argv[1], argv[2]);
    system(cmd);
}
