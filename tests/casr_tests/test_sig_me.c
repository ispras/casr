#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2)
    return 1;
  int ppid = getpid();
  char command[500] = {0};
  char *end;
  sprintf(command, "kill -s %ld %u", strtol(argv[1], &end, 10), ppid);
  system(command);
  pause();
  return 0;
}
