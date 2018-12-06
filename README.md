# asemu
32-bit x86 emulator using ncurses and capstone/keystone/unicorn

WARNING: This software is in **super ultra early alpha 0.00001** status! YMMV!

![asemu screenshot](http://i.imgur.com/qjP7P5I.png "asemu screenshot")

# Dependencies

 * libncurses
 * cmake
 * libcapstone
 * libkeystone
 * libunicorn

Install the first two (at least) with your package manager.  The other three can be installed with the 'deps.sh' script (tested on Ubuntu 16.04)


Known Issues:
  viewing the help screen while not full screen displays nothing
  At seeminly random times the program will look fine but will operate executing several instructions at once.
  When trying to "display" everything weird issues with the buffer being corrupted
