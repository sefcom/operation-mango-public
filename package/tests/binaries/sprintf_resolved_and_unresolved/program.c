
#include <stdio.h>
#include <stdlib.h>


void resolved() {
    char command[64];
    char *format_str = "ls -alh %s";
    char *dir = "~/";

    sprintf(command, format_str, dir);
    system(command);
}

void unresolved(char *augment) {
    char command[64];
    char *format_str = "ls %s";
    sprintf(command, format_str, augment);
    system(command);
}

int main(int argc, char **argv) {
    puts("--- fixed ---");
    resolved();
    puts("--- user controlled ---");
    unresolved(argv[1]);
    return 0;
}