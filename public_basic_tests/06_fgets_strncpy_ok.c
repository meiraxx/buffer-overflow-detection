#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  int control;
  char buf2[32];
  char buf1[64];

  control = 6;
  fgets(buf1, 64, stdin);
  strncpy(buf2, buf1, 32);

  return 0;
}