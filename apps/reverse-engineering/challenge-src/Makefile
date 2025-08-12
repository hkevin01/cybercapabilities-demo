CC=gcc
CFLAGS=-O0 -g -fno-stack-protector -no-pie
LDFLAGS=
SRC=challenge.c
BIN_DIR=bin
BIN=$(BIN_DIR)/challenge
STRIPPED=$(BIN_DIR)/challenge-stripped

all: $(BIN) $(STRIPPED)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN): $(SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC) $(LDFLAGS)

$(STRIPPED): $(BIN)
	cp $(BIN) $(STRIPPED)
	strip $(STRIPPED)

clean:
	rm -rf $(BIN_DIR)
