#include <stdio.h>
#include <stdlib.h>


int main(int argc, char *argv[]) {
  puts("***** main *****");

  for(int i=0; i<42; i++) {
    puts("***** looping *****");
  }

  system(argv[1]);

  return 0;
}
