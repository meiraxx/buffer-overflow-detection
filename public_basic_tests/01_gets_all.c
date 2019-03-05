#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  int control;
  char buf1[64];

  control = 1;
  gets(buf1);

  return 0;
}