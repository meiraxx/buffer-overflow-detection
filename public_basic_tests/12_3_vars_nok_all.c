#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  char buf4[64];
  char buf3[64];
  char buf2[32];
  char buf1[64];

  fgets(buf1, 64, stdin);
  strncpy(buf2, buf1, 32);
  strncpy(buf3, buf1, 64);
  strcpy(buf4, buf2);

  return 0;
}