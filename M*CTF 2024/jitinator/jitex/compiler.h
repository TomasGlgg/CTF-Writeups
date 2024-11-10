#include <vector>
#include <map>
#include "./vm.h"

#ifndef COMPILER 
#define COMPILER

#define REG_COUNT 4

#define JIT_ADDR 0x400000000 //prevent overwriting jit region

typedef unsigned char byte;

//I hope sometimes here will be normal optimised compiler...

class Compiler {
  public:
    Compiler();
    void compile(byte* instruction_mem,size_t start);
    void run(size_t number);
    byte* get_rwx();
  private:
    static std::vector<size_t> func_start;
    static byte* executable_memory;
};

#endif
