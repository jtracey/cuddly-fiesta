#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define MACHINE_IP inet_addr("127.0.0.1")
#define PORT 49152

int test_net(){
  int soc;
  uint16_t port = PORT;

  soc = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in connectAddress;
  memset(&connectAddress, 0, sizeof(connectAddress));
  connectAddress.sin_family = AF_INET;
  connectAddress.sin_addr.s_addr = MACHINE_IP;
  connectAddress.sin_port = htons(port);
  
  if(connect(soc, (struct sockaddr *) &connectAddress, sizeof(connectAddress)) < 0) {
    printf("failed to connect: %s\n", strerror(errno));
    return 1;
  }

  const char* message = "{\"ii\":1,\"nb\":5,\"na\":1558876259}";
  const char* sig = "........................................................................................";
  if(write(soc, message, strlen(message)+1) < 0) {
      printf("failed to write to socket\n");
      return 1;
  }
  if(write(soc, sig, 80) < 0) {
      printf("failed to write to socket\n");
      return 1;
  }
  return 0;
}

int main(){
  return test_net();
}
