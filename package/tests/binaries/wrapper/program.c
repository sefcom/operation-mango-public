#include <stdio.h>


void system_wrapper(char *command) {
    system(command);
}


void main(int argc, char** argv) {
    char command[0x40];
    snprintf(command, 0x40, "echo 'Executing: %s'", argv[1]);
    system_wrapper(command);
    snprintf(command, 0x40, "%s", argv[1]);
    system_wrapper(command);
}
