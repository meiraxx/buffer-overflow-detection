#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  int control;
  char buf3[32];
  char buf2[32];
  char buf1[32];

  control = 21;
  fgets(buf1, 34, stdin);
  strcpy(buf3, buf1);

  return 0;
}