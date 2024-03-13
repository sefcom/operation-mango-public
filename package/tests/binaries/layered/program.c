#include <stdio.h>
#include <stdlib.h>

void layer_1(char *arg1, char *arg2) {
    layer_2(arg1, arg2);
}

void layer_2(char *arg1, char *arg2) {
    layer_3(arg1, arg2);
}

void layer_3(char *arg1, char *arg2) {
    layer_4(arg1, arg2);
}

void layer_4(char *arg1, char *arg2) {
    layer_5(arg1, arg2);
}

void layer_5(char *arg1, char *arg2) {
    layer_6(arg1, arg2);
}

void layer_6(char *arg1, char *arg2) {
    layer_7a(arg1);
    layer_7b(arg2);
}

void layer_7a(char *arg1) {
    system(arg1);
}

void layer_7b(char *arg1) {
    system(arg1);
}

int main(int argc, char **argv, char **envp) {

    char *buf = "ls -la";
    layer_1(buf, argv[1]);

}
