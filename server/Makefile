.DEFAULT_GOAL := all 
.PHONY := all clean


ifeq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
$(info Cross compiling active)
CC = aarch64-none-linux-gnu-gcc
else
$(info  Cross compiling disable)
CC = gcc
endif
CCFLAGS = -Wall -Werror -g3 -O0
APP_NAME = aesdsocket
FILE_NAME = $(APP_NAME)

all: $(FILE_NAME).o
	$(CC) $^ -o $(APP_NAME) $(CCFLAGS)

$(FILE_NAME).o:
	$(CC) -c $(FILE_NAME).c -o $@ $(CCFLAGS)


clean:
	rm -f *.o
	rm -f $(FILE_NAME)
