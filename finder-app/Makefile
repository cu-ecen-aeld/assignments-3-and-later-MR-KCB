.DEFAULT_GOAL := all 
.PHONY := all clean


ifeq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
$(info Cross compiling active)
CC = aarch64-none-linux-gnu-gcc
else
$(info  Cross compiling disable)
CC = gcc
endif
APP_NAME = writer
FILE_NAME = writer

all: $(FILE_NAME).o
	$(CC) $^ -o $(APP_NAME)

$(FILE_NAME).o:
	$(CC) -c $(FILE_NAME).c -o $@


clean:
	rm -f *.o
	rm -f $(FILE_NAME)
