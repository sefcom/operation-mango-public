#include <unistd.h>
#include <stdio.h>


void main(int argc, char** argv) {
    char *args[4];
    args[0] = "echo";

    execlp(args[0], args[0], "Hello", argv[1], 0);
}
