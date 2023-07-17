from pwn import *
# Registers init config
REG_A = 0x40
REG_B = 0x80
REG_C = 0x1
REG_D = 0x8
REG_S = 0x20
REG_I = 0x2
REG_F = 0x4
# Instructions init config
INST_IMM = 0x1 
INST_STK = 0x80 
INST_ADD = 0x10 
INST_STM = 0x4 
INST_LDM = 0x20 
INST_JMP = 0x8 
INST_CMP = 0x2 
INST_SYS = 0x40 
# Syscalls numbers init config
SYS_OPEN       = 0x10
SYS_READ_MEM   = 0x1
SYS_WRITE      = 0x8
SYS_SLEEP      = 0x2
SYS_EXIT       = 0x4
SYS_READ_CODE  = 0x80

class Instruction():
    def __init__(self, op, arg1, arg2) -> None:
        self.op = op
        self.arg1 = arg1
        self.arg2 = arg2
    
    def to_bytes(self):
        return self.arg1.to_bytes(1,'big') + self.op.to_bytes(1,'big') + self.arg2.to_bytes(1,'big')
    def __add__(self, other):
        return self.to_bytes() + other.to_bytes()

class StackInstruction(Instruction):
    def __init__(self, arg1, arg2) -> None:
        super().__init__(INST_STK, arg1, arg2)

class PUSH(StackInstruction):
    def __init__(self, register) -> None:
        super().__init__(0, register)

class POP(StackInstruction):
    def __init__(self, register) -> None:
        super().__init__(register, 0)

class ImmediateInstruction(Instruction):
    def __init__(self, register, immediate) -> None:
        super().__init__(INST_IMM, register, immediate)

class MOVI(ImmediateInstruction):
    def __init__(self, register, immediate) -> None:
        super().__init__(register, immediate)
    
    def to_bytes(self):
        if type(self.arg2) == bytes:
            return self.arg1.to_bytes(1,'big') + self.op.to_bytes(1,'big') + self.arg2
        else:
            return super().to_bytes()

class Syscall(Instruction):
    def __init__(self, syscall_index, reg) -> None:
        super().__init__(INST_SYS, syscall_index, reg)

class Sys_OPEN(Syscall):
    def __init__(self, result_register) -> None:
        super().__init__(SYS_OPEN, result_register)

class Sys_READ_MEM(Syscall):
    def __init__(self, result_register) -> None:
        super().__init__(SYS_READ_MEM, result_register)

class Sys_EXIT(Syscall):
    def __init__(self, result_register) -> None:
        super().__init__(SYS_EXIT, result_register)

class Sys_WRITE(Syscall):
    def __init__(self, result_register) -> None:
        super().__init__(SYS_WRITE, result_register)
    

class Yan85Code():
    def __init__(self):
        self.instructions = []

    def add(self, instruction: Instruction):
        self.instructions.append(instruction)
    
    def to_bytes(self):
        bytes = b''
        for i in self.instructions:
            bytes += i.to_bytes()
        return bytes

payload = Yan85Code()

# Pushing filename onto the stack
for c in b'/flag\x00':
    payload.add(MOVI(REG_A, c))
    payload.add(PUSH(REG_A))

# yan_open = linux_open(&mem[REG_A], REG_B, REG_C)
payload.add(MOVI(REG_A, b'\x01'))
payload.add(MOVI(REG_B, b'\x00'))
payload.add(MOVI(REG_C, b'\x00'))
payload.add(Sys_OPEN(REG_D))

# yan_read_memory = linux_read(REG_A, &MEM[REG_B], REG_C)
payload.add(MOVI(REG_A, b'\x04'))
payload.add(MOVI(REG_B, b'\x00'))
payload.add(MOVI(REG_C, b'\x50'))
payload.add(Sys_READ_MEM(REG_D))

# yan_write = linux_write(REG_A, &MEM[REG_B], REG_C)
payload.add(MOVI(REG_A, b'\x01'))
payload.add(MOVI(REG_B, b'\x00'))
payload.add(MOVI(REG_C, b'\x50'))
payload.add(Sys_WRITE(REG_D))

payload.add(Sys_EXIT(REG_A))


s = ssh(host='pwncollege')
p = s.process('/challenge/babyrev_level22.0')

p.recvuntil(b'Please input your yancode: ')
p.sendline(payload.to_bytes())
p.interactive()

# pwn.college{EGPlPnnzhdPcOxkoRfs84_VM1iP.01N4IDL1UTNzEzW}