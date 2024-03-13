#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>


void* id(void *parameter) {
  return parameter;
}

void a(void *parameter) {
  id(parameter);
  system(parameter);
}

void b(void *parameter) {
  id(parameter);
  execve(parameter, NULL, NULL);
}


int main(int argc, char *argv[]) {
  puts("***** a *****");
  a(argv[1]);

  puts("***** b *****");
  b(argv[1]);

  return 0;
}
