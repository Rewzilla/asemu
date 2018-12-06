# asemu
32-bit x86 emulator using ncurses and capstone/keystone/unicorn

WARNING: This software is in **Beta** status! YMMV!

![asemu screenshot](http://i.imgur.com/qjP7P5I.png "asemu screenshot")

# Dependencies

 * libncurses
 * cmake
 * libcapstone
 * libkeystone
 * libunicorn

Install the first two (at least) with your package manager.  The other three can be installed with the 'deps.sh' script (tested on Ubuntu 16.04)


Known Issues:
  At seeminly random times the program will look fine but will operate executing several instructions at once.
  When trying to "display" everything, some times there is weird issues with the buffer being corrupted
  Scrolling seems to display interesting figures at times when it goes out of bounds
  Data and Bss do not always read in all forms of input correctly, usually stick with decimal
