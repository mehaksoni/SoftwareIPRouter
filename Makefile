all:

  gcc -shared -c -fPIC packet.c -o function1.o
  gcc -shared -Wl,-soname,library.so -o library.so function1.o
