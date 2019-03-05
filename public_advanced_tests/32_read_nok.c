#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  int control;
  char buf1[64];

  control = 32;
  read(STDIN_FILENO, buf1, 80);

  return 0;
}