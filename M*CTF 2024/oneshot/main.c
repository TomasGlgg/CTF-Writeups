#include <stdio.h>
#include <stdlib.h>

size_t get_value() {
  char number[32] = {0};
  puts("Enter value.");
  puts(">>");
  fgets(number,18,stdin);
  size_t value = strtol(number,number+16,16);
  return value;
}

void arbitrary_write(size_t* addr,size_t value) {
  *addr = value;
}

size_t arbitrary_read(size_t* addr) {
  return *addr;
}

void menu() {
  puts("Enter 1 to get more knowledge about program.");
  puts("Enter 2 to perform oneshot.");
  puts("Enter 3 to exit.");
  return;
}

void fflushx() {
  setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

int main(int argc,char** argv) {
  int64_t option = 0;
  fflushx();
  while(1) {
    menu();
    option = get_value();
    switch(option) {
      case 1:
      {
        puts("Getting knowledge...");
        size_t addr = get_value();
        size_t val = arbitrary_read(addr);
        printf("Your knowledge: %lx\n",val);
      }
      break;
      case 2:
      {
        puts("Performing oneshot...");
        puts("Entering address...");
        size_t addr = get_value();
        size_t val = get_value();
        puts("Making shot...");
        arbitrary_write(addr,val);
      }
      case 3:
        exit(0);
      break;
      default:
        puts("Invalid number");
      break;
    }

  }
  exit(0);
}
