#include <stdio.h>
#include <string.h>
#include <unistd.h>


void log(char *buf) {
    printf("YOU SAID: %s\n", buf);
}

void sub_func(char *buf) {
    sprintf(buf, "%s; echo 'DONE'", buf);
}

void alter_command(char *buf1, char *buf2) {
    strcat(buf1, buf2);
    sub_func(buf1);
}

void off_shoot_resolved(char *command) {
    log("OFFSHOOT RESOLVED");
    alter_command(command, " 'Hello World'");
    log(command);
    system(command);
}

void off_shoot_unresolved(char *command) {
    log("OFFSHOOT UNRESOLVED");
    char extras[0x40];
    memset(extras, 0, 0x40);
    read(0, extras, 0x40);
    int len = strlen(extras);
    if (extras[len-1] == '\n') {
        extras[len-1] = '\0';
    }
    alter_command(command, extras);
    log(command);
    system(command);
}

void main(int argc, char **argv) {
    char buf[0x64] = {"echo"};
    off_shoot_resolved(buf);
    memset(buf, 0, 0x64);
    memcpy(buf, "ls ", 4);
    off_shoot_unresolved(buf);

}