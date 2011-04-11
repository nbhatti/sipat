# makefile template for creating C programs

#################################################################
# sources & dependencies

SRCS := $(wildcard *.c)
HDRS := $(wildcard *.h)
DEP_IN = ${SRCS} ${HDRS}
OBJS := $(patsubst %.c,%.o,$(SRCS))

#################################################################

default:	${NAME}

${NAME}:	${OBJS}
		${CC} ${CFLAGS} ${LDFLAGS} ${INCLUDES} -o $@ ${OBJS} ${LIBS}

#################################################################
# common rules

%.o:	%.c
		${CC} ${CFLAGS} ${INCLUDES} -c $<

.PHONY:	install install-static install-shared install-headers install-dirs clean proper

proper: clean
		-@rm -f tags ID

clean:
		-@rm -f ${NAME} *.o *.d core core.* *~ Makefile.deps

ifneq ($(MAKECMDGOALS),proper)
ifneq ($(MAKECMDGOALS),clean)
-include $(SRCS:.c=.d)
endif
endif

%.d:	%.c
		@$(CC) -M $(CFLAGS) $(INCLUDES) $< > $@.$$$$; \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
		rm -f $@.$$$$

#################################################################
# instalation

install:	${NAME} install-dirs
			$(install-bin) $(NAME) $(bin-dir)

install-dirs:	$(bin-dir)

$(bin-dir):	
			mkdir -p $(bin-dir)

