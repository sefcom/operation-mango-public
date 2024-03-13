#include <stdlib.h>
#include <string.h>


void main(int argc, char** argv) {
    char *command1 = malloc(0x20);
    strncpy(command1, "ls -la", 0x1f);
    system(command1);

    char *command2 = malloc(0x20);
    strncpy(command2, argv[1], 0x1f);
    system(command2);

    free(command1);
    free(command2);
}