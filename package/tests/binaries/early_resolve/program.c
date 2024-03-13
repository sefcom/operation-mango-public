#include <stdlib.h>
#include <stdio.h>


void wrapper(char *command) {
    system(command);
}

void child() {
    char buf[0x40];
    char command[0x100];

    read(0, buf, 0x40);
    sprintf(command, "echo %s", buf);
    wrapper(command);
}

void parent_1() {
    child();
}

void parent_2() {
    child();
}

void nested_1(char *log) {
    printf("Log: %s\n", log);
    char *val = getenv("UNKNOWN");
    system(val);
}

void constant_1(char *buf) {
    system(buf);
}

void main(int argc, char **argv) {
    parent_1();
    parent_2();
    nested_1(argv[1]);
    constant_1("echo 'HELLO WORLD'");
}