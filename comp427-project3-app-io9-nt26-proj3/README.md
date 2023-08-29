# Comp427 / 541: App Security Project

## Application Security
The project specifications, as well as the corresponding course slide decks,
can be found on the Comp427 Piazza.

## Student Information
Please also edit _README.md_ and replace your instructor's name and NetID with your own:

_Student1 name_: Isabella Obermeier

_Student1 NetID_: io9

_Student2 name_: Nabillah Tanuwikanda

_Student2 NetID_: nt26

Your NetID is typically your initials and a numeric digit. That's
what we need here.

_If you contacted us in advance and we approved a late submission,
please cut-and-paste the text from that email here._

Extra credit?
```
[if you did any extra credit targets, please list them here]
```

_Lastly, don't forget that there are some written questions at the bottom of this file._

## Setup
You'll probably be running this with GitHub Codespaces, which sets up a virtual machine, in the cloud, with everything properly installed in it. This is much, much easier than trying to get your individual machines configured correctly. 

If you look at the top of this GitHub page, you'll see a green `<> Code` button. Click that, select the "Codespaces" tab, and then click the "New codespace" button. At this point, your cloud VM is now being intialized, which can take a few minutes. When it's done, you'll be looking at a version of Microsoft's
[Visual Studio Code](https://code.visualstudio.com/) that's running in your browser and connected to your VM. If you have VSCode installed on your computer, there's a button in your browser that will launch your desktop VSCode and connect it to the cloud. (You'll be asked to install some additional plugins for VSCode and to click
through a number of security permission dialogs, but only on the first time.)

Either way, whenever you edit a file or run a command, you're doing it on the cloud VM, not your personal computer. The VM also has its own copies of your files, which means that you need to be sure to do the usual Git operations (*commit* & *push*) so that your work is visible to your graders. You can double-check this by coming back to GitHub.com, and verifying that your commits are visible from the GitHub web page.

### The Unix shell and configuring your VM

At the bottom of the VSCode window, you can see a Unix terminal shell. If you don't see it on your desktop, then use the menus: Terminal → New Terminal. If you don't see it in your browser, you need to use the "hamburger" (≡) menu in the upper left, then Terminal → New Terminal.

The first thing you should do is run this:
```
cat /proc/sys/kernel/randomize_va_space
```

If it says `0`, you're good to go. If for some reason it says something else, like `2`, then you need to do one more thing:
```
sudo sysctl kernel.randomize_va_space=0 
```

If you see an error about things being read-only, then your virtual machine is misconfigured and the attacks you're going to be doing aren't going to work. *Hopefully*, that won't happen, but if it does, you might try going all the way back to the `<> Code` button, where there will now be a link to "manage all" your codespaces, and from there you can delete them. You can then go back to the `<> Code` button once more and restart things. If that's happening, then please also check Piazza, since it's probably happening to others as well.

Anyway, from that Unix shell, you can see the two subdirectories used by your project: `parser` and `targets`. You'll be starting with `targets`.

-  `cd targets`
- `./setcookie netid1 netid2` (this customizes the memory layout, just for your team, with your NetIDs, so every team will have slightly different attacks)
- `make` (this compiles everything)
-  If you run `echo hello | target0` and it tells you something like `Hi hello! Your grade is nil.` then everything is working correctly. If you see `Can't normalize stack position`, then it's time to find a labbie or TA or post on Piazza. Something is misconfigured on your VM.

### Python2 vs. Python3

This project was originally designed when Python3 was the crazy new thing and Python2 was widely used. Now that's changing. In your VM, `python` gives you Python 3.8.12. In order to get Python2, you need to explicitly run `python2`. This is what our autograder does.
Note that you need to use what's provided with the Python distribution you were given. External libraries won't be included and won't work with our autograder.

(If you really, really want to use Python3, please discuss this with your professors in advance, so we can make sure that the autograder can deal with this, somehow. In future years, we'll turn off Python2 and go entirely with Python3, but not this time.)

### Can I run this on my personal computer directly?

We're explicitly disabling some important security features from the OS kernel that protect you against others trying to conduct the very attacks that you're doing. 
You're safer to use Docker (useful instructions for [connecting Docker and VSCode](https://code.visualstudio.com/docs/remote/containers)). Docker claims to support [x86 via QEMU emulation](https://docs.docker.com/desktop/mac/apple-silicon/). It's probably going to be much faster and easier for you to just use the cloud VM.

## Written questions
These questions are based on 
[Smashing the Stack for Fun & Profit : Revived](https://comp427.rice.edu/static/proj4/stack-smashing.pdf),
which you and your partner should read together and answer these questions.


_In normal operation, when a C string is five characters long (e..g, "Hello"), and assuming
every character takes exactly one byte of memory, how many bytes
are necessary to represent that C string?_

```
We need 6 bytes of memory, 1 for each character and an extra byte for the terminating null space 0x0.
```

_On page 4-5, the author shows the use of the C `strcpy()` function,
which copies a C string from one address to another. If you wanted to
use `malloc()` to allocate enough memory for a copy of a string and
`strcpy()` to make the copy, what would you write? Please put a
snippet of C code below. (You may assume that every character is
exactly one byte long; don't worry about Unicode.)_

```
char *source = (char*)malloc(sizeof(char)* 256);
char *copy = strcpy(source, str);
```

_The author observes that `strcpy()` has no way to know whether the
destination buffer is too small for the string it's writing, and shows
how you can use this to overwrite the stack, ultimately targeting the
`execve()` system call (page 9 of the PDF,
[documentation for execve](https://man7.org/linux/man-pages/man2/execve.2.html)). 
If you instead wanted to target `system()`
([documentation](https://man7.org/linux/man-pages/man3/system.3.html)),
what would you have to change?_

```
Since system() returns a signal after a command (usually the execl() command), it can fail with any of the same errors as fork and has a bug when using hyphens. When specficially targetting the system() command, the path can be modified and exploited and give an attacker privleges.
```

_If you look at the Makefile included in this project, you'll see that
it uses some peculiar flags to the C compiler:_

```
target0: CFLAGS += -fno-stack-protector -z execstack 
```

_What do these flags do? You may use your favorite search engine,
and/or read gcc's documentation, but describe their impact in your own words._

```
CFLAGS are customizable argument options when building a file and compiling C code. They specify additional switches for C compiler and tell the MAKEFILE how to handle the code.
```

_Consider section 8 ("Writing an Exploit"), which describes writing
shellcode to the stack and executing it. If the program were compiled
with `-fno-stack-protector`, but not `-z execstack`, would the attack
still succeed or would it fail? What if it were compiled with `-z
execstack` but not `-fno-stack-protector`?_

```
If attempting to attack the stack through buffer overflow, including only -fno-stack-protector would allow an overflow attack to commence. Omitting the use of execstack would set the stack to non-executable by default and therefore not execute the overflowed stack, preventing the attacker from succeeding. On the other hand, using only execstack (ommitting -fno-stack-protector), means that StackGuard protector is enabled and should ideally protect overflowed stacks from being executed, but heaps can still be run.
```
