#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  int control;
  char buf2[32];
  char buf1[64];

  control = 3;
  fgets(buf1, 45, stdin);
  strcpy(buf2, buf1);

  return 0;
}