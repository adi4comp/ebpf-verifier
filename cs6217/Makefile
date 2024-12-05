
CLANG = clang
CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -I.

SRC_DIR = .

OBJ_DIR = .


SRC_FILES := $(wildcard $(SRC_DIR)/*.bpf.c)

OBJ_FILES := $(patsubst $(SRC_DIR)/%.bpf.c, $(OBJ_DIR)/%.bpf.o, $(SRC_FILES))


.PHONY: all
all: $(OBJ_FILES)


.PHONY: this
this:
	@if [ -z "$(file)" ]; then \
		echo "Please specify a file with 'make file=<filename>'"; \
		exit 1; \
	fi
	$(CLANG) $(CFLAGS) -c $(SRC_DIR)/$(file).bpf.c -o $(OBJ_DIR)/$(file).bpf.o
	@echo "Compiled $(file).bpf.c to $(file).bpf.o"


$(OBJ_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "Compiled $< to $@"

 
.PHONY: clean
clean:
	rm -f $(OBJ_DIR)/*.bpf.o
	@echo "Cleaned up object files"
