# makefile template for creating C programs

#################################################################
# sources & dependencies

SRCS := $(wildcard *.cpp)
HDRS := $(wildcard *.h)
DEP_IN = ${SRCS} ${HDRS}
OBJS := $(patsubst %.cpp,%.o,$(SRCS))

#################################################################

default:	${NAME}

${NAME}:	${OBJS}
		${CXX} ${CXXFLAGS} ${LDFLAGS} ${INCLUDES} -o $@ ${OBJS} ${LIBS}

#################################################################
# common rules

%.o:	%.cpp
		${CXX} ${CXXFLAGS} ${INCLUDES} -c $<

.PHONY:	install install-static install-shared install-headers install-dirs clean proper

proper: clean
		-@rm -f ID tags

clean:
		-@rm -f ${NAME} *.o *.d core core.* *~ Makefile.deps

ifneq ($(MAKECMDGOALS),proper)
ifneq ($(MAKECMDGOALS),clean)
-include $(SRCS:.cpp=.d)
endif
endif

%.d:	%.cpp
		@$(CXX) -M $(CXXFLAGS) $(INCLUDES) $< > $@.$$$$; \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
		rm -f $@.$$$$

#################################################################
# instalation

install:	${NAME} install-dirs
			$(install-bin) $(NAME) $(bin-dir)

install-dirs:	$(bin-dir)

$(bin-dir):	
			mkdir -p $(bin-dir)

