CC = gcc
CFLAGS =

INJECTOR = injector
INJECTOR_SRC = main.c injector.c

TOOL = libinjected
TOOL_SRC = libinjected.c modules/*.c

all: $(INJECTOR) $(TOOL)

$(INJECTOR): $(INJECTOR_SRC)
	$(CC) $(CFLAGS) $(INJECTOR_SRC) -o $(INJECTOR)

$(TOOL): $(TOOL_SRC)
	$(CC) -shared -fPIC $(CFLAGS) $(TOOL_SRC) -o $(TOOL).so


debug: CFLAGS += -g -DDEBUG
debug: INJECTOR := $(INJECTOR)_debug
debug: TOOL := $(TOOL)_debug
debug: $(INJECTOR) $(TOOL)

clean:
	rm -f $(INJECTOR) $(INJECTOR)_debug $(TOOL).so $(TOOL)_debug.so

.PHONY: all debug clean