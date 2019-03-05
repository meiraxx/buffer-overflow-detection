#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  int control;
  char buf3[32];
  char buf2[32];
  char buf1[32];

  control = 31;
  fgets(buf1, 32, stdin);
  fgets(buf2, 32, stdin);
  snprintf(buf3, 32, "%s%s", buf1, buf2);

  return 0;
}