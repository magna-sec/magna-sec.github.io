---
title: VR - First Post Blues
date: 2024-02-26 09:16:11 +/-TTTT
categories: [VR]
tags: [vr]     # TAG names should always be lowercase
---
# Whats the point of this "blog post"? 
We're going to take a HTB challenge and try and dive a little deeper than normal. In essence the challenge is reversing a Linux ELF binary and extracting three passwords. This can easily be done with GDB, by watching the `strcmp` calls or by literally stepping through the whole thing.

However, this time we're gonna go through the challenge purely with Ghidra to increase our current reverse engineering skillset.

![alt text](/assets/images/21-11-2024/cat.gif "meow")

Challenge: [Hunting License](https://app.hackthebox.com/challenges/Hunting%20License)

 

## Binary Enumeration"? 
What is this binary? Let's take a look:
```
magna@dojo:~$ file license
license: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5be88c3ed329c1570ab807b55c1875d429a581a7, for GNU/Linux 3.2.0, not stripped
```

From the output we can deduce:
- The file is 64-bit ELF file, meaning this will run on x86-64 bit Linux systems.
- LSB (Least Significant Byte) endianness.
- x86 instruction set.
- Dynamically Linked. Indicates that the binary is dynamically linked, meaning it relies on external shared libraries (e.g., .so files).
- Uses the standard Linux dynamic linker `/lib64/ld-linux-x86-64.so.2`
- Minimum kernel version of GNU/Linux 3.2.0
- Not Stripped meaning information is still present in the binary. This makes it easier for us to reverse.

From the above information we can get even more information, primarily concerning external libarires it may be using and any information present in the binary due to not being stripped.

```bash
magna@dojo:~$ ldd license 
	linux-vdso.so.1 (0x00007ffef73c0000)
	libreadline.so.8 => /lib/x86_64-linux-gnu/libreadline.so.8 (0x000078b4fef0b000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x000078b4fec00000)
	libtinfo.so.6 => /lib/x86_64-linux-gnu/libtinfo.so.6 (0x000078b4feed9000)
	/lib64/ld-linux-x86-64.so.2 (0x000078b4fef71000)
```

We can now see the external shared libarries in use:
- `linux-vdso.so.`: A virtual shared library provided by the Linux kernel. Mapped to `0x00007ffef73c0000` in process memory at runtime.
- `libreadline.so.8`: Provides functions for command-line text input, including features like line editing, history, and autocompletion.  Mapped to `0x000078b4fef0b000` in process memory at runtime.
- `libc.so.6`: The GNU C Library, mapped to `0x000078b4fec00000` in process memory at runtime.
- `libtinfo.so.6`: Provides low-level terminal handling functions, used for programs that need direct interaction with terminal capabilities. Maped to `0x000078b4feed9000` in process memory at runtime.
- `ld-linux-x86-64.so.2`: Tthe standard Linux dynamic linker, mapped to `0x000078b4fef71000` in process memory at runtime.

Let's also find the processes main function address (this will help later):
```
magna@dojo:~$ objdump -d license 
<SNIP>
0000000000401172 <main>:
  401172:	55                   	push   %rbp
  401173:	48 89 e5             	mov    %rsp,%rbp
  401176:	48 83 ec 10          	sub    $0x10,%rsp
  40117a:	bf 08 20 40 00       	mov    $0x402008,%edi
  40117f:	e8 bc fe ff ff       	call   401040 <puts@plt>
  401184:	bf 30 20 40 00       	mov    $0x402030,%edi
  401189:	e8 b2 fe ff ff       	call   401040 <puts@plt>
  40118e:	bf 88 20 40 00       	mov    $0x402088,%edi
  401193:	e8 a8 fe ff ff       	call   401040 <puts@plt>
  401198:	e8 d3 fe ff ff       	call   401070 <getchar@plt>
  40119d:	88 45 ff             	mov    %al,-0x1(%rbp)
  4011a0:	80 7d ff 79          	cmpb   $0x79,-0x1(%rbp)
  4011a4:	74 20                	je     4011c6 <main+0x54>
  4011a6:	80 7d ff 59          	cmpb   $0x59,-0x1(%rbp)
  4011aa:	74 1a                	je     4011c6 <main+0x54>
  4011ac:	80 7d ff 0a          	cmpb   $0xa,-0x1(%rbp)
  4011b0:	74 14                	je     4011c6 <main+0x54>
  4011b2:	bf dd 20 40 00       	mov    $0x4020dd,%edi
  4011b7:	e8 84 fe ff ff       	call   401040 <puts@plt>
  4011bc:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  4011c1:	e8 ba fe ff ff       	call   401080 <exit@plt>
  4011c6:	b8 00 00 00 00       	mov    $0x0,%eax
  4011cb:	e8 ba 00 00 00       	call   40128a <exam>
  4011d0:	bf f0 20 40 00       	mov    $0x4020f0,%edi
  4011d5:	e8 66 fe ff ff       	call   401040 <puts@plt>
  4011da:	b8 00 00 00 00       	mov    $0x0,%eax
  4011df:	c9                   	leave  
  4011e0:	c3                   	ret  
<SNIP>
```
Lovely it's `0x0000000000401172`! We now have a general idea of the binary and also have it's starting point (main address). Though its been snipped we are also presented with other function addresses:
```
00000000004011e1 <reverse>:
0000000000401237 <xor>:
000000000040128a <exam>:
```

Let's now run the binary to see the output we're working with:
```
magna@dojo:~$ ./license 
So, you want to be a relic hunter?
First, you're going to need your license, and for that you need to pass the exam.
It's short, but it's not for the faint of heart. Are you up to the challenge?! (y/n)
y
Okay, first, a warmup - what's the first password? This one's not even hidden: test
Not even close!
```

As with previous challenges we're presented with a prompt asking for a password. As this binary is `not stripped` there could potentially be strings in memory. Oh wait.. strings ;).
```
magna@dojo:~$ strings license 
/lib64/ld-linux-x86-64.so.2
__gmon_start__
readline
exit
puts
getchar
strcmp
<SNIP>
So, you want to be a relic hunter?
First, you're going to need your license, and for that you need to pass the exam.
It's short, but it's not for the faint of heart. Are you up to the challenge?! (y/n)
Not many are...
Well done hunter - consider yourself certified!
Okay, first, a warmup - what's the first password? This one's not even hidden: 
PasswordNumeroUno
Not even close!
Getting harder - what's the second password? 
You've got it all backwards...
Your final test - give me the third, and most protected, password: 
Failed at the final hurdle!
;*3$"
0wTdr0wss4P
G{zawR}wUz}r
GCC: (Debian 10.2.1-6) 10.2.1 20210110
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
main.c
__FRAME_END__
<SNIP>
.fini_array
.dynamic
.got
.got.plt
.data
.bss
.comment
```

Not stripping the binary has given us two potentialy passwords:
```
PasswordNumeroUno
0wTdr0wss4P
```

From the previous `objdump` it could be infered there's 3 passwords, we have 2 currently. Also with the previous `objdump` we see a function called `reverse` and we have a string that looks suspicously like a password reversed.. hmmphhh?:
```
PasswordNumeroUno
P4ssw0rdTw0
```
![alt text](/assets/images/21-11-2024/nice.gif "....nice")

There's no real remenants for the third password that appears to be `XOR`ed judging by the avaiable functions. Let's test the last two passwords:
```
magna@dojo:~$ ./license 
So, you want to be a relic hunter?
First, you're going to need your license, and for that you need to pass the exam.
It's short, but it's not for the faint of heart. Are you up to the challenge?! (y/n)
y
Okay, first, a warmup - what's the first password? This one's not even hidden: PasswordNumeroUno
Getting harder - what's the second password? P4ssw0rdTw0
Your final test - give me the third, and most protected, password: password
Failed at the final hurdle!
```
Looking good, it's time to summon Ghidra.
![alt text](/assets/images/21-11-2024/gr.gif "Green Ranger")

## Ghidra Time 

`Symbol Tree -> Functions -> main`

![alt text](/assets/images/21-11-2024/ghidra_main.png "Ghidra main")

Lovely we see our main function address matches up and we're presented with a decompiled main function!

The main function appears to be simple, takes in a users input, convert to a `char` and compare against 3 defined `char`s and act accordingly. Simply put.. if anything other than `y`/`Y` is entered the program flows into the `if` block and ultiamtely executes `exit(-1)` terminating the program.
```c
if (((user_input != 'y') && (user_input != 'Y')) && (user_input != '\n'))
{
    puts("Not many are...");
    exit(-1);
}
```

If the user enters the correct input (why wouldnt you?) then `exam()` is called.
This is the meat and potatoes of this challenge (its that the right term?):
![alt text](/assets/images/21-11-2024/challenges.png "Challenges")

Let's go through each one of these at a time.

### Challenge 1
```c
chal_1 = strcmp(user_input,"PasswordNumeroUno");
if (chal_1 != 0) {
    puts("Not even close!");
    exit(-1);
}
free(user_input);
```

As these challenges progress in difficulty this is the easiest of the three. The password is literally in a `strcmp`!

Password: `PasswordNumeroUno`


### Challenge 2
```c
char_2 = 0;
local_14 = 0;
reverse(&char_2,t,11);
user_input = (char *)readline("Getting harder - what\'s the second password? ");
chal_1 = strcmp(user_input,(char *)&char_2);
if (chal_1 != 0) {
    puts("You\'ve got it all backwards...");
    exit(-1);
}
free(user_input);
```

One issue we have is `t` is being passed into `reverse`. However, in Ghidra `t` is represented as an undefined array:
![alt text](/assets/images/21-11-2024/t_array.png "Array")

Hmphhh, `right click -> Data -> Choose Data Type -> type "char" -> char - BuiltInTypes/char -> Ok`:
![alt text](/assets/images/21-11-2024/t_char_array.png "Char Array")

Lovely! It's the string we saw earlier, although it could be presumed this was being passed into the function its best to double check.

Clicking on `reverse(&char_2,t,11)` in ghidra we are presented with the follow code `Reverse` code:
```c
void reverse(long buffer,long password,ulong length)

{
  int i;
  
  for (i = 0; (ulong)(long)i < length; i = i + 1) {
    *(undefined *)(buffer + i) = *(undefined *)(password + (length - (long)i) + -1);
  }
  return;
}
```

We could say "yeah this just reverses the string" but that's no fun... how does it do it!?

On initial inspection it takes in 3 variables, buffer, password and a length. `buffer` where the reverse `char`s will be stored, `password` the `t` array with password reversed, `11` the length of the `password` array (10 `char`s followed by a null byte `00`).

As Ghidra decompiles code it can add in unessary code due to compiler optimations etc. So let's use the code provide by Ghidra and write our own reverse function. 

Our Code using the function from Ghidra:
```c
#include <stdio.h>

void reverse(char *buffer, char *password, long length)
{
  int i;
  
  for (i = 0; i < length; i = i + 1) {
    *(buffer + i) = *(password + (length - i) + -1);
  }
  return;
}

int main() {
    char str[] = "0wTdr0wss4P";
    short length = 11;
    char buffer[12];

    reverse(buffer, str, length);
    
    printf("Original: %s\n", str);
    printf("Reversed: %s\n", buffer);
    
    return 0;
}
```
```bash
magna@dojo:~$ ./reverse 
Original: 0wTdr0wss4P
Reversed: P4ssw0rdTw0
```

Obviously there's a lot of optimsation that can be done but I wanted to keep the code close to the Ghidra output.

Essentially the first byte is taken from `password` and put at the end of `buffer` so its filled from the back.
Like:
```
0wTdr0wss4P
^
__________0

0wTdr0wss4P
 ^
_________w0

0wTdr0wss4P
  ^
________Tw0

0wTdr0wss4P
   ^
_______dTw0

0wTdr0wss4P
    ^
______rdTw0

0wTdr0wss4P
     ^
____0wrdTw0

0wTdr0wss4P
      ^
____w0rdTw0

0wTdr0wss4P
       ^
___sw0rdTw0

0wTdr0wss4P
        ^
__ssw0rdTw0

0wTdr0wss4P
         ^
_4ssw0rdTw0

0wTdr0wss4P
          ^
P4ssw0rdTw0
```

Yep sounds like a classic reverse haha!

Password: `P4ssw0rdTw0`

### Challenge 3
```c
local_38 = 0;
local_30 = 0;
local_28 = 0;
xor(&local_38,t2,17,19);
user_input = (char *)readline(
		       "Your final test - give me the third, and most protected, password: "
		       );
chal_1 = strcmp(user_input,(char *)&local_38);
if (chal_1 != 0) {
    puts("Failed at the final hurdle!");
    exit(-1);
}
free(user_input);
```
The same as challenge 2 was have an array, this time called `t2`. Though these aren't `char`s they can be represented as such.

`right click -> Data -> Choose Data Type -> type "char" -> char - BuiltInTypes/char -> Ok`:
![alt text](/assets/images/21-11-2024/t2_char_array.png "Char 2 Array")

Wait... I remember this from the `strings` output... yep `G{zawR}wUz}r`

Anyway in Ghidra we see a call to the function ``

Clicking on `xor(&local_38,&t2,17,19)` in ghidra we are presented with the follow code `xor` code:
```c
void xor(long buffer, long ciphertext, ulong length, byte key)
{
  int i;
  
  for (i = 0; (ulong)(long)i < length; i = i + 1) {
    *(byte *)(buffer + i) = *(byte *)(ciphertext + i) ^ key;
  }
  return;
}
```

This code is very similar to challenge 2 in that it iterates over a memory address, essentially take first item xor with key and repeat.

My tided up version:
```c
#include <stdio.h>

typedef unsigned char       byte;

void xor(byte *buffer, byte *ciphertext, short length, byte key)
{
  int i;
  
  for (i = 0; i < length; i = i + 1) {
    *(byte *)(buffer + i) = *(byte *)(ciphertext + i) ^ key;
  }
  return;
}

int main() {
    byte hex_string[] = {
        0x47, 0x7B, 0x7A, 0x61, 0x77, 0x52, 0x7D, 0x77,
        0x55, 0x7A, 0x7D, 0x72, 0x7F, 0x32, 0x32, 0x32,
	    0x13
    };
    short length = 17;
    byte key = 19;
    byte buffer[12];

    xor(buffer, hex_string, length, key);
    
    printf("Reversed: %s\n", buffer);
    
    return 0;
}
```
```
magna@dojo:~$ ./xor 
Reversed: ThirdAndFinal!!!
```
Let's just do the first 3 characters in the XOR for visibility sake:
```
01000111 0x47
00010011 19
 ^ ^ ^  
01010100 T

01111011 0x7B
00010011 19
 ^^ ^
01101000 h

01111010 0x7A
00010011 19
 ^^ ^  ^
01101001 i
```

Again improvements in the code could be implemented but I wanted to keep it close to the Ghidra output for comparison.

Password: `ThirdAndFinal!!!`

## The Finale

Alright the last part, we now have all 3 passwords. First let's test these all work:
```
magna@dojo:~$ ./license 
So, you want to be a relic hunter?
First, you're going to need your license, and for that you need to pass the exam.
It's short, but it's not for the faint of heart. Are you up to the challenge?! (y/n)
y
Okay, first, a warmup - what's the first password? This one's not even hidden: PasswordNumeroUno
Getting harder - what's the second password? P4ssw0rdTw0
Your final test - give me the third, and most protected, password: ThirdAndFinal!!!
Well done hunter - consider yourself certified!
```

Though no flag? Oh yes you need to spin up their server.

```
magna@dojo:~$ nc 83.136.254.158 39456
What is the file format of the executable?
> 
```

Well that's certainly different to the binary we have, let's continue.
We have all the answers to the questions so let's be very lazy and write a python script to submit the whole thing. 
Though the script is likely going to be some static varirables and just submitting them this is good practice for later when we need to interact with a service.

```python
from sys import argv,exit
from socket import socket,AF_INET,SOCK_STREAM

def connect(host:str, port:int) -> socket:
    """
    Establishes a TCP connection to a remote host and port.

    Args:
        host (str): The IP address or hostname of the server to connect to.
        port (int): The port number to connect to on the server.

    Returns:
        socket.socket: A socket object that is connected to the remote host and port.
    
    Example:
        client_socket = connect("127.0.0.1", 8080)
        print(f"Connected to server: {client_socket}")
    """
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"Connected to {host}:{port}")
    
    return client_socket

def submit_answer(con:socket, answer:str) -> None:
    """
    Receives data from the given socket connection, prints the data, and sends a response when
    a specific condition (the presence of '>' in the data) is met.

    Args:
        con (socket.socket): The socket object representing the connection to the server.
        answer (str): The answer to submit when the condition is met.

    Returns:
        None: This function does not return a value.

    Example:
        submit_answer(client_socket, "42")
    """
    print(f"Answer: {answer}")
   
    while True:
        data = con.recv(1024)
        
        print(f"Received: {data.decode()}")
        
        if ">" in data.decode():
            con.sendall(answer.encode())
            break    

def main():
    # Connection go brr
    if len(argv) != 3:
        print("Usage: python client.py <host> <port>")
        exit(1)

    host = argv[1]
    port = int(argv[2])

    con = connect(host, port)

    # All the answers
    answers = "Elf","x86-64", "libreadline.so.8", "00401172", "5", "PasswordNumeroUno", "0wTdr0wss4P", "P4ssw0rdTw0", "19", "ThirdAndFinal!!!"

    for answer in answers:
        submit_answer(con, answer)

    # Flag Time!
    response = con.recv(1024)
    flag = response.decode()
    flag = flag.split(' ')[-1]
    flag = flag[1:-2]
    print(f"Flag: {flag}")


if __name__ == "__main__":
    main()
```


There we go! The flag:
![alt text](/assets/images/21-11-2024/flag.png "Flag")

## Conclusion
Well.. that's how to take an easy HackTheBox challenge and dive a tad deeper, it's all good practice. It may seem like a lot for an easier challenge but overall it's about creating a metholodgy and really understanding why and how these flags are "hidden" and not just getting the flag and not learning anything!

![alt text](/assets/images/21-11-2024/completed-it-mate.gif "Jay")


