CC=gcc
WARN=-Wall
OUT=bt_passthrough
SRC=bt_passthrough.c

all:
	$(CC) $(WARN) $(SRC) -o $(OUT)


clean:
	rm -f $(OUT)


.PHONY: clean all
