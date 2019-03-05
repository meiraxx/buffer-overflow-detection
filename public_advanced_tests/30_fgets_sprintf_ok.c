#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  int control;
  char buf3[64];
  char buf2[32];
  char buf1[32];

  control = 30;
  fgets(buf1, 32, stdin);
  fgets(buf2, 32, stdin);
  sprintf(buf3, "%s%s", buf1, buf2);

  return 0;
}