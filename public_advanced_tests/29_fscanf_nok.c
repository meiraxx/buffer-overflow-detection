#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  int control;
  char buf1[48];

  control = 29;
  fscanf(stdin, "%s", buf1);

  return 0;
}