#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  int control;
  char buf2[32];
  char buf1[64];

  control = 33;
  fgets(buf1, 45, stdin);
  buf1[31] = '\0';
  strcpy(buf2, buf1);

  return 0;
}