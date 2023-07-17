# Solving level 22 - Last level of reverse engineering challenges
To see the notes I took during the reverse engineering process, see notes.pdf.

1. Reverse engineering the instructions_loop allowed me to understand how an instruction is represented, with three bytes. 
2. Then going through the interpreter_instruction code made me understand how the arguments were used for parsing the instructions.
3. At this point it was clear that i did not had to reverse engineer everything, but just what is needed to perform open, read and write syscalls.
4. After getting to know the syscalls syntax, I started writing down the initial configuration of the remote machine (registers, instructions, ecc). This was easily doable by trying intructions and seeing the result.
5. At this point, initial configuration is known, so I started scripting to retrieve the flag. I coded few classes to represent the behavior of the Yan85 instructions, after which it was easy to test different behaviors.

# My _Yan85 shellcode_ 
```python
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
```