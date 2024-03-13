#include <unistd.h>
#include <stdio.h>


void main(int argc, char** argv) {
    char *args[4];
    args[0] = "./other_prog";
    args[1] = "Hello!";
    args[2] = argv[1];
    args[3] = 0;

    printf("Running: %s %s %s\n", args[0], args[1], args[2]);
    execve(args[0], args, 0);
}
