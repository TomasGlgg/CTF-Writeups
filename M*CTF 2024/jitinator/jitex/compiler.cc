#include "compiler.h"
#include <unistd.h>
#include <sys/mman.h>

byte* Compiler::executable_memory;
std::vector<size_t> Compiler::func_start;

Compiler::Compiler() {
  executable_memory = (byte*)mmap((void*)JIT_ADDR,0x4000,PROT_READ |  PROT_WRITE | PROT_EXEC,MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE,-1,0);
  func_start.push_back(0);
}

void Compiler::run(size_t number) {
  size_t start = func_start.at(number);
  void (*func)() = (void(*)())(executable_memory+start);
  asm("mov $0x300000000,%r15"); //load into r15 data pointer
  func();
}

byte* Compiler::get_rwx() {
  return executable_memory;
}
