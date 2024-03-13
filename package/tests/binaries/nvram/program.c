#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "nvram_lib.h"


int main(int argc, char *argv[]) {
  char* command = acosNvramConfig_get("command1");
  system(command);

  command = acosNvramConfig_get("command2");
  system(command);

  acosNvramConfig_set("command1", "ls -la");
  return 0;
}
