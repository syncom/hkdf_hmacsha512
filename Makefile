# For Linux or any machines with gcc compiler
CC = gcc
CPP = g++

# Uncomment for production code
#CFLAGS = -I/usr/local/include -Wall -O2
# Uncomment the following line for Windows/MinGW
#CFLAGS = -DWIN_BUILD -I/usr/local/include -Wall -O2

# For Linux 
CFLAGS =  -I/usr/local/include -I. -Wall -O0 -g
LDFLAGS = -L/usr/local/lib -lsodium

# For SunOS
#CFLAGS = -Aa

SRC = hkdf_hmacsha512.c

OBJ = $(SRC:.c=.o)

%.o:%.c
	$(CC) -c $< $(CFLAGS)

all: test_hkdf_hmacsha512

test_hkdf_hmacsha512: test_hkdf_hmacsha512.o $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) test_hkdf_hmacsha512.o \
	-o test_hkdf_hmacsha512 $(LDFLAGS)


clean:
	rm -rf $(OBJ) test_hkdf_hmacsha512 *.o
