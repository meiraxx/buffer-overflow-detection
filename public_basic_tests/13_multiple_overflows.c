#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  char buf3[32];
  int control;
  char buf2[16];
  char buf1[64];

  control = 13;
  fgets(buf1, 64, stdin);
  strcpy(buf2, buf1);
  strcpy(buf3, buf1);


  return 0;
}