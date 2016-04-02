#include "verify.h"
#include <stdio.h>
#include <string.h>

int main(int argc, const char* argv[]){
  char *json;
  unsigned char *sig;

  if(argc < 2) {
    printf("Insufficient arguments\n");
    return 1;
  }

  if (!strcmp(argv[1], "verify")){
    if (argc < 4) {
      printf("verify requires a mode and port number argument\n");
      return 1;
    }
    verify_run_mode(argv);
  }
  else {
    printf("Invalid argument: %s\n", argv[1]);
    return 1;
  }
  return 0;
}
