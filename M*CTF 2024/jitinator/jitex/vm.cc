#include "vm.h"
#include <memory>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#define DATA_ADDR 0x300000000
#define CODE_ADDR 0x500000000

class Interpreter;

byte* Interpreter::data_memory;
byte* Interpreter::code_memory;
uint32_t Interpreter::ip;
uint32_t Interpreter::flags;
std::vector<uint32_t> Interpreter::registers;
std::map<byte,std::shared_ptr<Instruction>> Interpreter::handlers;

Interpreter::Interpreter(size_t register_count) {
  registers.resize(register_count);
  data_memory = (byte*)mmap((void*)DATA_ADDR,0x100*0x1000,PROT_READ | PROT_WRITE,MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE,-1,0);
  code_memory = (byte*)mmap((void*)CODE_ADDR,0x1000,PROT_READ | PROT_WRITE,MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE,-1,0);
  //add bytecode install
  handlers[0x1] = std::make_shared<MOVRR>();
  handlers[0x2] = std::make_shared<MOVRV>();
  handlers[0x3] = std::make_shared<MOVRM>();
  handlers[0x4] = std::make_shared<MOVMR>();
  handlers[0x21] = std::make_shared<ADDRR>();
  handlers[0x22] = std::make_shared<ADDRV>();
  handlers[0x11] = std::make_shared<XORRR>();
  handlers[0x12] = std::make_shared<XORRV>();
  handlers[0x60] = std::make_shared<CMPRR>();
  handlers[0x50] = std::make_shared<JUMP>();
  handlers[0x51] = std::make_shared<JE>();
  handlers[0x52] = std::make_shared<JL>();
  handlers[0x70] = std::make_shared<IOOUT>();
  handlers[0x71] = std::make_shared<IOIN>();
  flags = 0;
  ip = 0;
}

void Interpreter::install_bytecode(std::vector<byte>& bytecode) {
  int i = 0;
  was_compiled = false;
  if(bytecode.size() > 1000)
    throw("Error: too much bytes.");
  for(auto j : bytecode) {
    code_memory[i++] = j;
  }
}

bool Interpreter::is_compiled() {
  return was_compiled;
}

void Interpreter::load_instruction() {
  byte opcode = code_memory[ip];
  current = handlers.at(opcode);
}

void Interpreter::dispatch() {
  load_instruction();
  current->set(code_memory,ip);
  current->execute();
  ip += current->get_size();
  return;
}

void Interpreter::start() {
  ip = 0;
  flags = 0;
  while(code_memory[ip] != 0) {
    dispatch();  
  }
}

void Interpreter::compile_bytecode(byte* exec_memory,size_t func_start) {
  memset(exec_memory,0,0x4000);
  was_compiled = true;
  ip = 0;
  size_t local_pos = func_start;
  while(code_memory[ip] != 0) {
    load_instruction();
    current->set(code_memory,ip);
    current->compile(exec_memory,local_pos);
    ip+=current->get_size();
    local_pos+=current->get_compiled_size(); //get compiled size
  }
  exec_memory[local_pos] = 0xc3; //ret
}

//Instructions
byte Instruction::get_size() {
  return size;
}

byte Instruction::get_compiled_size() {
  return compiled_size;
}

void Instruction::set_size(byte sz) {
  size = sz;
}

void Instruction::set_compiled_size(byte sz) {
  compiled_size = sz;
}

//MOV 
//
void MOVRR::execute() {
  Interpreter::registers.at(r1) = Interpreter::registers.at(r2);
}

void MOVRR::set(byte* code_mem, size_t pos) {
  r1 = code_mem[pos+1];
  r2 = code_mem[pos+2];
}

//compile mov from register to register 

int MOVRR::compile(byte* memory,size_t pos) {
  memory[pos] = 0x89; //mov register to register
  switch(r1) {
    case 0:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc0; //mov eax,eax
        break;
        case 1:
          memory[pos+1] = 0xd8; //mov eax,ebx
        break;
        case 2:
          memory[pos+1] = 0xc8; //mov eax,ecx
        break;
        case 3:
          memory[pos+1] = 0xd0; //mov eax,edx
        break;
        default:
        throw("Invalid r2 number when compiling function");
    break;
    }
    break;
    case 1:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc3; //mov ebx,eax
        break;
        case 1:
          memory[pos+1] = 0xdb; //mov ebx,ebx
        break;
        case 2:
          memory[pos+1] = 0xcb; //mov ebx,ecx
        break;
        case 3:
          memory[pos+1] = 0xd3; //mov ebx,edx
        break;
        default:
          throw("Invalid r2 number when compiling function");
        break;
    }
    break;
    case 2:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc1; //mov ecx,eax
        break;
        case 1:
          memory[pos+1] = 0xd9; //mov ecx,ebx
        break;
        case 2:
          memory[pos+1] = 0xc9; //mov ecx,ecx
        break;
        case 3:
          memory[pos+1] = 0xd1; //mov ecx,edx
        break;
        default:
          throw("Invalid r2 number when compiling function");
        break;
    }
    break;
    case 3:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc2; //mov edx,eax
        break;
        case 1:
          memory[pos+1] = 0xda; //mov edx,ebx
        break;
        case 2:
          memory[pos+1] = 0xca; //mov edx,ecx
        break;
        case 3:
          memory[pos+1] = 0xd2; //mov edx,edx
        break;
        default:
          throw("Invalid r2 number when compiling function");
        break;
    }
    break;
    default:
      throw("Invalid r1 number when compiling function");
    break;
  }
  return 2;
}

void MOVRM::execute() {
  Interpreter::registers.at(reg) = Interpreter::data_memory[addr];
}

void MOVRM::set(byte* code_mem, size_t pos) {
  reg = code_mem[pos+1];
  addr = *(uint32_t*)(code_mem+pos+2);
}

int MOVRM::compile(byte* memory,size_t pos) {
  memory[pos++] = 0x49;
  memory[pos++] = 0x8d;
  memory[pos++] = 0x87; //lea rax, [r15+addr], r15 contains data memory;
  *(uint32_t*)(memory+pos) = addr;
  pos+=4;
  memory[pos++] = 0x8b; //mov register num dword ptr [rax];
  switch(reg) {
    case 0:
      memory[pos++] = 0x00; //mov eax,[rax]
    break;
    case 1:
      memory[pos++] = 0x18; //mov ebx,[rax]
    break;
    case 2:
     memory[pos++] = 0x8; //mov ecx,[rax]
    break;
    case 3:
     memory[pos++] = 0x10; //mov edx,[rax]
    break;

  }
  return 9;
}

void MOVMR::execute() {
  *(uint32_t*)(Interpreter::data_memory+addr) = Interpreter::registers.at(reg);
}

void MOVMR::set(byte* code_mem, size_t pos) {
  reg = code_mem[pos+5];
  addr = *(uint32_t*)(code_mem+pos+1);
}

int MOVMR::compile(byte* memory,size_t pos) {
  memory[pos++] = 0x49;
  memory[pos++] = 0x8d;
  memory[pos++] = 0xbf; //lea rdi, [r15+addr], r15 contains data memory;
  *(uint32_t*)(memory+pos) = addr;
  pos+=4;
  memory[pos++] = 0x89; //mov [rdi] register;
  switch(reg) {
    case 0:
      memory[pos++] = 0x07; //mov [rdi],eax
    break;
    case 1:
      memory[pos++] = 0x1f; //mov ebx,[rax]
    break;
    case 2:
     memory[pos++] = 0x0f; //mov ecx,[rax]
    break;
    case 3:
     memory[pos++] = 0x17; //mov edx,[rax]
    break;
  }
  return 9;
}

void MOVRV::execute() {
  Interpreter::registers.at(reg) = value;
}

void MOVRV::set(byte* code_mem, size_t pos) {
  reg = code_mem[pos+1];
  value = *(uint32_t*)(code_mem+pos+2);
}

int MOVRV::compile(byte* memory,size_t pos) {
  switch(reg) {
    case 0:
      memory[pos++] = 0xb8; //mov eax, value
    break;
    case 1:
      memory[pos++] = 0xbb; //mov ebx, value
    break;
    case 2:
     memory[pos++] = 0xb9; //mov ecx, value
    break;
    case 3:
     memory[pos++] = 0xba; //mov edx, value
    break;

  }
  *(uint32_t*)(memory+pos) = value;
  return 5;
}
//XOR

void XORRR::execute() {
  Interpreter::registers.at(r1) ^= Interpreter::registers.at(r2);
}

void XORRR::set(byte* code_mem, size_t pos) {
  r1 = code_mem[pos+1];
  r2 = code_mem[pos+2];
}

int XORRR::compile(byte* memory,size_t pos) {
  memory[pos] = 0x31; //xor register to register
  switch(r1) {
    case 0:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc0; //xor eax,eax
        break;
        case 1:
          memory[pos+1] = 0xd8; //xor eax,ebx
        break;
        case 2:
          memory[pos+1] = 0xc8; //xor eax,ecx
        break;
        case 3:
          memory[pos+1] = 0xd0; //xor eax,edx
        break;
        default:
        throw("Invalid r2 number when compiling function");
    break;
    }
    break;
    case 1:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc3; //xov ebx,eax
        break;
        case 1:
          memory[pos+1] = 0xdb; //xov ebx,ebx
        break;
        case 2:
          memory[pos+1] = 0xcb; //xov ebx,ecx
        break;
        case 3:
          memory[pos+1] = 0xd3; //xov ebx,edx
        break;
        default:
          throw("Invalid r2 number when compiling function");
        break;
    }
    break;
    case 2:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc1; //xor ecx,eax
        break;
        case 1:
          memory[pos+1] = 0xd9; //xov ecx,ebx
        break;
        case 2:
          memory[pos+1] = 0xc9; //xov ecx,ecx
        break;
        case 3:
          memory[pos+1] = 0xd1; //xov ecx,edx
        break;
        default:
          throw("Invalid r2 number when compiling function");
        break;
    }
    break;
    case 3:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc2; //xov edx,eax
        break;
        case 1:
          memory[pos+1] = 0xda; //xov edx,ebx
        break;
        case 2:
          memory[pos+1] = 0xca; //xov edx,ecx
        break;
        case 3:
          memory[pos+1] = 0xd2; //xov edx,edx
        break;
        default:
          throw("Invalid r2 number when compiling function");
        break;
    }
    break;
    default:
      throw("Invalid r1 number when compiling function");
    break;
  }
  return 2;
}

void XORRV::execute() {
  Interpreter::registers.at(reg) ^= value;
}

void XORRV::set(byte* code_mem, size_t pos) {
  reg = code_mem[pos+1];
  value = *(uint32_t*)(code_mem+pos+2);
}

int XORRV::compile(byte* memory,size_t pos) {
  switch(reg) {
    case 0:
      memory[pos++] = 0x48; //xor rax, value
      memory[pos++] = 0x35;
    break;
    case 1:
      memory[pos++] = 0x81; //xor ebx, value
      memory[pos++] = 0xf3;
    break;
    case 2:
      memory[pos++] = 0x81; //xor ecx, value
      memory[pos++] = 0xf1;
    break;
    case 3:
      memory[pos++] = 0x81; //xor edx, value
      memory[pos++] = 0xf2;
    break;

  }
  *(uint32_t*)(memory+pos) = value;
  return 6;
}

//ADD
void ADDRV::execute() {
  Interpreter::registers.at(reg) += value;
}

void ADDRV::set(byte* code_mem, size_t pos) {
  reg = code_mem[pos+1];
  value = *(uint32_t*)(code_mem+pos+2);
}

int ADDRV::compile(byte* memory,size_t pos) {
  switch(reg) {
    case 0:
      memory[pos++] = 0x48; //add rax, value
      memory[pos++] = 0x05;
    break;
    case 1:
      memory[pos++] = 0x81; //add ebx, value
      memory[pos++] = 0xc3;
    break;
    case 2:
      memory[pos++] = 0x81; //add ecx, value
      memory[pos++] = 0xc1;
    break;
    case 3:
      memory[pos++] = 0x81; //add edx, value
      memory[pos++] = 0xc2;
    break;

  }
  *(uint32_t*)(memory+pos) = value;
  return 6;
}

void ADDRR::execute() {
  Interpreter::registers.at(r1) += Interpreter::registers.at(r2);
}

void ADDRR::set(byte* code_mem, size_t pos) {
  r1 = code_mem[pos+1];
  r2 = code_mem[pos+2];
}

int ADDRR::compile(byte* memory,size_t pos) {
  memory[pos] = 0x01; //add register to register
  switch(r1) {
    case 0:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc0; //add eax,eax
        break;
        case 1:
          memory[pos+1] = 0xd8; //add eax,ebx
        break;
        case 2:
          memory[pos+1] = 0xc8; //add eax,ecx
        break;
        case 3:
          memory[pos+1] = 0xd0; //add eax,edx
        break;
        default:
        throw("Invalid r2 number when compiling function");
    break;
    }
    break;
    case 1:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc3; //add ebx,eax
        break;
        case 1:
          memory[pos+1] = 0xdb; //add ebx,ebx
        break;
        case 2:
          memory[pos+1] = 0xcb; //add ebx,ecx
        break;
        case 3:
          memory[pos+1] = 0xd3; //add ebx,edx
        break;
        default:
          throw("Invalid r2 number when compiling function");
        break;
    }
    break;
    case 2:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc1; //add ecx,eax
        break;
        case 1:
          memory[pos+1] = 0xd9; //add ecx,ebx
        break;
        case 2:
          memory[pos+1] = 0xc9; //add ecx,ecx
        break;
        case 3:
          memory[pos+1] = 0xd1; //add ecx,edx
        break;
        default:
          throw("Invalid r2 number when compiling function");
        break;
    }
    break;
    case 3:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc2; //add edx,eax
        break;
        case 1:
          memory[pos+1] = 0xda; //add edx,ebx
        break;
        case 2:
          memory[pos+1] = 0xca; //add edx,ecx
        break;
        case 3:
          memory[pos+1] = 0xd2; //add edx,edx
        break;
        default:
          throw("Invalid r2 number when compiling function");
        break;
    }
    break;
    default:
      throw("Invalid r1 number when compiling function");
    break;
  }
  return 2;
}
//CMP

void CMPRR::execute() {
  if(r1 == r2)
    Interpreter::flags |= 1; //0001
  else if( r1 < r2)
    Interpreter::flags |= 3; //0010
  else
    Interpreter::flags = 0;
}

void CMPRR::set(byte* code_mem, size_t pos) {
  r1 = code_mem[pos+1];
  r2 = code_mem[pos+2];
}

int CMPRR::compile(byte* memory,size_t pos) {
  memory[pos] = 0x39; //cmp register to register
  switch(r1) {
    case 0:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc0; //cmp eax,eax
        break;
        case 1:
          memory[pos+1] = 0xd8; //cmp eax,ebx
        break;
        case 2:
          memory[pos+1] = 0xc8; //cmp eax,ecx
        break;
        case 3:
          memory[pos+1] = 0xd0; //cmp eax,edx
        break;
        default:
        throw("Invalid r2 number when compiling function");
    break;
    }
    break;
    case 1:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc3; //cmp ebx,eax
        break;
        case 1:
          memory[pos+1] = 0xdb; //cmp ebx,ebx
        break;
        case 2:
          memory[pos+1] = 0xcb; //cmp ebx,ecx
        break;
        case 3:
          memory[pos+1] = 0xd3; //cmp ebx,edx
        break;
        default:
          throw("Invalid r2 number when compiling function");
        break;
    }
    break;
    case 2:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc1; //cmp ecx,eax
        break;
        case 1:
          memory[pos+1] = 0xd9; //cmp ecx,ebx
        break;
        case 2:
          memory[pos+1] = 0xc9; //cmp ecx,ecx
        break;
        case 3:
          memory[pos+1] = 0xd1; //cmp ecx,edx
        break;
        default:
          throw("Invalid r2 number when compiling function");
        break;
    }
    break;
    case 3:
      switch(r2) {
        case 0:
          memory[pos+1] = 0xc2; //cmp edx,eax
        break;
        case 1:
          memory[pos+1] = 0xda; //cmp edx,ebx
        break;
        case 2:
          memory[pos+1] = 0xca; //cmp edx,ecx
        break;
        case 3:
          memory[pos+1] = 0xd2; //cmp edx,edx
        break;
        default:
          throw("Invalid r2 number when compiling function");
        break;
    }
    break;
    default:
      throw("Invalid r1 number when compiling function");
    break;
  }
  return 2;
}
//JMP

void JUMP::execute() {
  byte* current = Interpreter::code_memory+Interpreter::ip+2; //start opcode to count which number of bytes we should jump
  size_t jump_value = 0;
  for(size_t i = 0; i < value; i++) {
    byte opcode = *current;
    jump_value+=Interpreter::handlers.at(opcode)->get_size();
    current+=Interpreter::handlers.at(opcode)->get_size();
  }
  Interpreter::ip+=jump_value;
}

void JUMP::set(byte* code_mem, size_t pos) {
  value = code_mem[pos+1];
}

int JUMP::compile(byte* memory,size_t pos) {
  byte* current = Interpreter::code_memory+Interpreter::ip+2; //start opcode to count which number of bytes we should jump
  size_t jump_value = 0;
  for(size_t i = 0; i < value; i++) {
    byte opcode = *current;
    jump_value+=Interpreter::handlers.at(opcode)->get_compiled_size();
    current+=Interpreter::handlers.at(opcode)->get_size();
  }
  memory[pos++] = 0xeb;
  memory[pos] = jump_value-2;
  return 2;
}

void JE::execute() {
  if((Interpreter::flags & 1) == 0)
    return;
  byte* current = Interpreter::code_memory+Interpreter::ip+2; //start opcode to count which number of bytes we should jump
  size_t jump_value = 0;
  for(size_t i = 0; i < value; i++) {
    byte opcode = *current;
    jump_value+=Interpreter::handlers.at(opcode)->get_size();
    current+=Interpreter::handlers.at(opcode)->get_size();
  }
  Interpreter::ip+=jump_value;
  Interpreter::flags = 0;
}

void JE::set(byte* code_mem, size_t pos) {
  value = code_mem[pos+1]; //number of command to skip ; TODO support backward jump
}

int JE::compile(byte* memory,size_t pos) {
  byte* current = Interpreter::code_memory+Interpreter::ip+2; //start opcode to count which number of bytes we should jump
  size_t jump_value = 0;
  for(size_t i = 0; i < value; i++) {
    byte opcode = *current;
    jump_value+=Interpreter::handlers.at(opcode)->get_compiled_size();
    current+=Interpreter::handlers.at(opcode)->get_size();
  }
  memory[pos++] = 0x74;
  memory[pos] = jump_value-2;
  return 0;
}

void JL::execute() {
  if((Interpreter::flags & 3) == 0)
    return;
  byte* current = Interpreter::code_memory+Interpreter::ip+2; //start opcode to count which number of bytes we should jump
  size_t jump_value = 0;
  for(size_t i = 0; i < value; i++) {
    byte opcode = *current;
    jump_value+=Interpreter::handlers.at(opcode)->get_size();
    current+=Interpreter::handlers.at(opcode)->get_size();
  }
  Interpreter::ip+=jump_value;
  Interpreter::flags = 0;
}

void JL::set(byte* code_mem, size_t pos) {
  value = code_mem[pos+1];
}

int JL::compile(byte* memory,size_t pos) {
  byte* current = Interpreter::code_memory+Interpreter::ip+2; //start opcode to count which number of bytes we should jump
  size_t jump_value = 0;
  for(size_t i = 0; i < value; i++) {
    byte opcode = *current;
    jump_value+=Interpreter::handlers.at(opcode)->get_compiled_size();
    current+=Interpreter::handlers.at(opcode)->get_size();
  }
  memory[pos++] = 0x7c;
  memory[pos] = jump_value-2;
  return 2;
}

//IO

void IOOUT::execute() {
  byte* buf = Interpreter::data_memory+addr;
  write(1,buf,sizex);
}

void IOOUT::set(byte* code_mem, size_t pos) {
  sizex = code_mem[pos+1];
  addr = *(uint32_t*)(code_mem+pos+2);
}

int IOOUT::compile(byte* memory,size_t pos) {
  memory[pos++] = 0x49;
  memory[pos++] = 0x8d;
  memory[pos++] = 0xb7;
  *(uint32_t*)(memory+pos) = addr; //lea rsi, r15+addr;
  pos+=4;
  memory[pos++] = 0x31;
  memory[pos++] = 0xff; //xor edi edi

  memory[pos++] = 0xff;
  memory[pos++] = 0xc7; //inc edi
                    
  memory[pos++] = 0x31;
  memory[pos++] = 0xd2; //xor edx,edx
                        //
  memory[pos++]= 0xb2;
  memory[pos++] = sizex;//mov dl,size

  memory[pos++] = 0x31;
  memory[pos++] = 0xc0; //xor eax,eax
                        //
  memory[pos++] = 0xff;
  memory[pos++] = 0xc0; //inc eax

  memory[pos++] = 0x0f;
  memory[pos++] = 0x05; //syscall
  return 21;
}

void IOIN::execute() {
  byte* buf = Interpreter::data_memory+addr;
  read(0,buf,sizex);
}

void IOIN::set(byte* code_mem, size_t pos) {
  sizex = code_mem[pos+1];
  addr = *(uint32_t*)(code_mem+pos+2);
}

int IOIN::compile(byte* memory,size_t pos) {
  memory[pos++] = 0x49;
  memory[pos++] = 0x8d;
  memory[pos++] = 0xb7;
  *(uint32_t*)(memory+pos) = addr; //lea rsi, r15+addr;
  pos+=4;
  memory[pos++] = 0x31;
  memory[pos++] = 0xff; //xor edi edi
                    
  memory[pos++] = 0x31;
  memory[pos++] = 0xd2; //xor edx,edx
                        //
  memory[pos++]= 0xb2;
  memory[pos++] = sizex; //mov dl,size
                        //
  memory[pos++] = 0x31;
  memory[pos++] = 0xc0; //xor eax,eax
                        //
  memory[pos++] = 0x0f;
  memory[pos++] = 0x05; //syscall
  return 17;
}
