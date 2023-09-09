LIBS := -libverbs -lrdmacm
CFLAGS := -std=gnu99 -Wall -Wextra -Wunused -fpie

all: CFLAGS += -O2 -DNDEBUG
all: initiator target

debug: CFLAGS += -O0 -g -fsanitize=address
debug: initiator target

initiator: initiator.o pool.o
	$(CC) -o $@ $^ ${CFLAGS} ${LIBS}

target: target.o pool.o
	$(CC) -o $@ $^ ${CFLAGS} ${LIBS}

-include *.d
%.o:%.c
	$(CC) -c $< ${CFLAGS} ${LIBS} -MMD -MP -o $@

.PHONY: clean
clean:
	rm -f initiator target *.o rx_* tx_* *.d
