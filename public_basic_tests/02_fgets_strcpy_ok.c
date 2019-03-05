#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  int control;
  char buf2[32];
  char buf1[64];

  control = 2;
  // do not forget that fgets reads N-1 chars but writes 32
  // buf1[32] = '\0'
  fgets(buf1, 32, stdin);
  strcpy(buf2, buf1);

  return 0;
}