LIBS := -libverbs -lrdmacm
CFLAGS := -Wall -Wextra -Wunused -fpie

all: CFLAGS += -O2 -DNDEBUG
all: initiator target

debug: CFLAGS += -O0 -g -fsanitize=address
debug: initiator target

initiator: initiator.o pool.o
	$(CC) -o $@ $^ ${CFLAGS} ${LIBS}

target: target.o pool.o
	$(CC) -o $@ $^ ${CFLAGS} ${LIBS}

.PHONY: clean
clean:
	rm -f initiator target *.o rx_* tx_*
