#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  char buf2[64];
  char buf1[64];

  fgets(buf1, 32, stdin);
  fgets(buf2, 32, stdin);
  strcat(buf2, buf1); // buf2 is now at most 31 + 31 bytes + '\0'

  return 0;
}