#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "nvram_lib.h"


int main(int argc, char *argv[]) {
  acosNvramConfig_set("command1", "ls -la");
  acosNvramConfig_set("command2", argv[1]);
  return 0;
}
