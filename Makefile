CC	= g++
CFLAGS 	= -Wall
TARGET 	= send_arp

all : $(TARGET)


$(TARGET) : send_arp.o
	$(CC) $(CFLAGS) -o $(TARGET) send_arp.o -lpcap

clean:
	rm -rf $(TARGET) send_arp.o
