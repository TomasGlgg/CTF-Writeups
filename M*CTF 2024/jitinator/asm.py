#!/usr/bin/python3
import struct 
f = open('code.asm')

lines = f.readlines()

#command encoding - opcode, bytes for 1 arg, bytes for 2nd arg

keywords = {"MOVRR" : [1,1,1],
            "MOVRV" : [2,1,4],
            "MOVRM" : [3,1,4], 
            "MOVMR" : [4,4,1],
            "ADDRR" : [0x21,1,1],
            "ADDRV" : [0x22,1,4],
            "XORRR" : [0x11,1,1],
            "XORRV" : [0x12,1,4],
            "CMPRR" : [0x60,1,1],
            "JUMP" : [0x50,1],
            "JE" : [0x51,1],
            "JL" : [0x52,1],
            "IOOUT" : [0x70,1,4],
            "IOIN" : [0x71,1,4]}

bytecode = b''

for line in lines:
    command = line.split(',')
    print(command)
    for key in keywords.keys():
        if command[0] == key:
            command_struct = keywords[key]
            bytecode+=command_struct[0].to_bytes(1,'little')
            for num,val in zip(command_struct[1:],command[1:]):
                val = int(val,16)
                bytecode+=val.to_bytes(num,'little')
print(len(bytecode))
print(bytecode)

with open('asm.bin', 'wb') as of:
    of.write(b'1\n')
    of.write(bytecode)
    of.write(b'\n3\n2\n')
