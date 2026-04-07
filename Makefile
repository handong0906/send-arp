TARGET = send-arp-practice

all: main.c
	gcc  -o $(TARGET) main.c -lpcap

clean:
	rm -rf $(TARGET)