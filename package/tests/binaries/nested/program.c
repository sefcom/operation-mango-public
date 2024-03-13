#include <stdio.h>
#include <stdlib.h>


void b() { }

void a(int i) {
  if (i < 10) {
    b();
  }

  int j = 42;
}

int main(int argc, char *argv[]) {
  a(argc);

  system(argv[1]);

  return 0;
}
