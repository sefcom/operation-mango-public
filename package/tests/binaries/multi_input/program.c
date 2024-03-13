#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#define PORT 8080


void vuln(char *cmdline, int sock_fd, int file_fd) {
    char buf1[0x40];
    char buf2[0x40];
    char buf3[0x40];
    char buf4[0x40];
    char buf5[0x40];
    char cmd[1024];

    read(0, buf1, 0x40);
    read(sock_fd, buf2, 0x40);
    read(file_fd, buf3, 0x40);
    recv(sock_fd, buf4, 0x40, 0);
    FILE *f = fopen("/etc/passwd", "r");
    fgets(buf5, 0x40, f);

    sprintf(cmd, "%s%s%s%s%s%s", buf1, buf2, buf3, buf4, buf5, cmdline);
    system(cmd);
}

int main(int argc, char *argv[]) {
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = { 0 };
    char* hello = "Hello from server";

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr*)&address,
             sizeof(address))
        < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket
         = accept(server_fd, (struct sockaddr*)&address,
                  (socklen_t*)&addrlen))
        < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    int file_fd = open("/etc/passwd", O_RDONLY);
    vuln(argv[1], new_socket, file_fd);
    return 0;
}
