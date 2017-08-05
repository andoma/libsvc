-include mk/$(shell uname).mk

CFLAGS_opt := -fno-omit-frame-pointer
CFLAGS_opt += -fsanitize=address

ifeq ($(shell uname),Linux)
CFLAGS_opt += -Og
else
CFLAGS_opt += -O0
endif

LDFLAGS    += -fsanitize=address
