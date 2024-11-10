#include <cstdint>
#include <iostream>
#include <map>
#include <cinttypes>
#include <vector>
#include <memory>

#ifndef VM
#define VM


//When compile we consider r1 - eax, r2 - ebx, r3 - ecx, r4 - edx

typedef unsigned char byte;

class Instruction;

class Interpreter {
  public:
    Interpreter(size_t register_count); //register count is not custom(now is 4 for jit)
    void dispatch();
    void load_instruction();
    void install_bytecode(std::vector<byte>& bytecode);
    void compile_bytecode(byte* memory,size_t func_start);
    void start();
    bool is_compiled();
    static std::map<byte,std::shared_ptr<Instruction>> handlers; //map instruction : handler;
    static std::vector<uint32_t> registers;
    static byte* data_memory;
    static byte* code_memory;
    static uint32_t ip;
    static uint32_t flags;
  private:
    bool was_compiled = false;
    std::shared_ptr<Instruction> current;
};

class Instruction {
  public:
    Instruction() = default;
    virtual void execute() = 0; //execute thos instruction
    virtual int compile(byte* memory,size_t pos) = 0; //compile into real assembler - return number of bytes
    virtual void set(byte* code_mem,size_t pos) = 0;
    byte get_opcode();
    byte get_size();
    byte get_compiled_size();
    void set_size(byte sz);
    void set_compiled_size(byte sz);
  private:
    byte opcode = 0;
    byte size = 0;
    byte compiled_size = 0;
};

class MOVRR : public Instruction {
  public:
    MOVRR() { set_size(1+1+1); set_compiled_size(2);}
    virtual void execute() override;
    virtual int compile(byte* memory,size_t pos) override;
    virtual void set(byte* code_mem,size_t pos) override;
  private:
    byte opcode = 0x01;
    char r1;
    char r2;
};

class MOVRV : public Instruction {
  public:
    MOVRV() { set_size(1+1+4); set_compiled_size(5);}
    virtual void execute() override;
    virtual int compile(byte* memory,size_t pos) override;
    virtual void set(byte* code_mem,size_t pos) override;
  private:
    byte opcode = 0x02;
    byte reg;
    uint32_t value;
};

class MOVRM : public Instruction {
  public:
    MOVRM() { set_size(1+1+4); set_compiled_size(9);}
    virtual void execute() override;
    virtual int compile(byte* memory,size_t pos) override;
    virtual void set(byte* code_mem,size_t pos) override;
  private:
    byte opcode = 0x03;
    byte reg;
    uint32_t addr;
};

class MOVMR : public Instruction {
  public:
    MOVMR() { set_size(1+4+1); set_compiled_size(9);}
    virtual void execute() override;
    virtual int compile(byte* memory,size_t pos) override;
    virtual void set(byte* code_mem,size_t pos) override;
  private:
    byte opcode = 0x04;
    uint32_t addr;
    byte reg;
};

class ADDRR : public Instruction {
  public:
    ADDRR() { set_size(1+1+1); set_compiled_size(2);}
    virtual void execute() override;
    virtual int compile(byte* memory,size_t pos) override;
    virtual void set(byte* code_mem,size_t pos) override;
  private:
    byte opcode = 0x21;
    byte r1;
    byte r2;
    byte size = 1+1+1;
};

class ADDRV : public Instruction {
  public:
    ADDRV() { set_size(1+1+4); set_compiled_size(6);}
    virtual void execute() override;
    virtual int compile(byte* memory,size_t pos) override;
    virtual void set(byte* code_mem,size_t pos) override;
  private:
    byte opcode = 0x22;
    byte reg;
    uint32_t value;
    byte size = 1+1+4;
};


class XORRR : public Instruction {
  public:
    XORRR() { set_size(1+1+1); set_compiled_size(2);}
    virtual void execute() override;
    virtual int compile(byte* memory,size_t pos) override;
    virtual void set(byte* code_mem,size_t pos) override;
  private:
    byte opcode = 0x11;
    byte r1;
    byte r2;
    byte size = 1+1+1;
};

class XORRV : public Instruction {
  public:
    XORRV() { set_size(1+1+4); set_compiled_size(6);}
    virtual void execute() override;
    virtual int compile(byte* memory,size_t pos) override;
    virtual void set(byte* code_mem,size_t pos) override;
  private:
    byte opcode = 0x12;
    byte reg;
    uint32_t value;
    byte size = 1+1+4;
};

class CMPRR : public Instruction {
  public:
    CMPRR() { set_size(1+1+1); set_compiled_size(2);}
    virtual void execute() override;
    virtual int compile(byte* memory,size_t pos) override;
    virtual void set(byte* code_mem,size_t pos) override;
  private:
    byte opcode = 0x60;
    byte r1;
    byte r2;
    byte size = 1+1+1; //jump over some instructions
};

class JUMP : public Instruction {
  public:
    JUMP() { set_size(1+1);set_compiled_size(2);}
    virtual void execute() override;
    virtual int compile(byte* memory,size_t pos) override;
    virtual void set(byte* code_mem,size_t pos) override;
  private:
    byte opcode = 0x50;
    byte value;
    byte size = 1+1; //jump over some instructions
};

class JE : public Instruction {
  public:
    JE() { set_size(1+1); set_compiled_size(2);}
    virtual void execute() override;
    virtual int compile(byte* memory,size_t pos) override;
    virtual void set(byte* code_mem,size_t pos) override;
  private:
    byte opcode = 0x51;
    byte value;
    byte size = 1+1; //jump over some instructions
};

class JL : public Instruction {
  public:
    JL() { set_size(1+1); set_compiled_size(2);}
    virtual void execute() override;
    virtual int compile(byte* memory,size_t pos) override;
    virtual void set(byte* code_mem,size_t pos) override;
  private:
    byte opcode = 0x52;
    byte value;
    byte size = 1+1; //jump over some instructions
};

class IOOUT : public Instruction {
  public:
    IOOUT() { set_size(1+1+4); set_compiled_size(21);}
    virtual void execute() override;
    virtual int compile(byte* memory,size_t pos) override;
    virtual void set(byte* code_mem,size_t pos) override;
  private:
    byte opcode = 0x70;
    byte sizex;
    uint32_t addr;
    byte size = 1+1+4; //jump over some instructions
};

class IOIN : public Instruction {
  public:
    IOIN() { set_size(1+1+4); set_compiled_size(17);}
    virtual void execute() override;
    virtual int compile(byte* memory,size_t pos) override;
    virtual void set(byte* code_mem,size_t pos) override;
  private:
    byte opcode = 0x71;
    byte sizex;
    uint32_t addr;
    byte size = 1+1+4; //jump over some instructions
};

#endif
