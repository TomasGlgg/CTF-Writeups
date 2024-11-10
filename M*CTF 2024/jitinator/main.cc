#include <iostream>
#include "./jitex/compiler.h"
#include "./jitex/vm.h"

void menu() {
  std::cout<<"Enter 1 to load vm code."<<"\n";
  std::cout<<"Enter 2 to execute vm code."<<"\n";
  std::cout<<"Enter 3 to compile vm code."<<"\n";
  std::cout<<">>"<<"\n";
}

int get_int() {
  int val = 0;
  std::cin>>val;
  return val;
}
int main() {
  Interpreter vm(REG_COUNT);
  Compiler cmplr;
  int option;
  while(true) {
    menu();
    option = get_int();
    switch(option) {
      case 1:
      {
        std::string input;
        std::cout<<"Enter bytecode"<<"\n";
        std::cout<<">>"<<"\n";
        std::vector<byte> bytex; 
        std::cin>>input;
        for(auto i : input)
          bytex.push_back(i);
        vm.install_bytecode(bytex);
      }
      break;
      case 2:
        std::cout<<"Starting vm...."<<"\n";
        if(!vm.is_compiled())
          vm.start();
        else
          cmplr.run(0); //run compiled function
        std::cout<<"Execution finished"<<"\n";
      break;
      case 3:
        std::cout<<"Staring compilation..."<<"\n";
        vm.compile_bytecode(cmplr.get_rwx(),0);
        std::cout<<"Compilation finished"<<"\n";
      break;
      default:
        std::cout<<"Invalid option"<<"\n";
      break;
    }
  }
}
