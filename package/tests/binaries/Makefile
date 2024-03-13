CC=gcc

PROGRAMS := $(wildcard */program.c)
DEBUG_FLAGS := -gdwarf -fvar-tracking-assignments

all: $(PROGRAMS)

clean:
	rm $(wildcard */program)

$(PROGRAMS): $@
	@echo
	@echo $@:
	$(CC) -o $(subst .c,,$@) $(DEBUG_FLAGS) $@

# Override `memcpy_resolved_and_unresolved/program.c`'s recipe to add specific flags.
memcpy_resolved_and_unresolved/program.c:
	@echo
	@echo $@:
	$(CC) -o $(subst .c,,$@) $(DEBUG_FLAGS) -fno-builtin-memcpy $@

.PHONY: all clean $(PROGRAMS)
