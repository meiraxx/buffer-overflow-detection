#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  char buf2[64];
  char buf1[64];

  fgets(buf1, 64, stdin);
  fgets(buf2, 32, stdin);
  strncat(buf2, buf1, 32);  // buf2 is now at most 31bytes + 32 (new) + '\0'

  return 0;
}