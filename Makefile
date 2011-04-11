# CFLAGS=-Wall -g
# export CFLAGS

SUBDIRS=callflow_diagrams cfanal

.PHONY: subdirs $(SUBDIRS) 

# clean install tags proper

# we need sub_goals without 'all' target
sub_goals = $(patsubst all,,$(MAKECMDGOALS))

subdirs: $(SUBDIRS)

$(SUBDIRS):	
			-@echo "Making $(sub_goals) in $@" ; $(MAKE) $(sub_goals) -C $@

all:	subdirs

proper:	clean
		-@rm -f ID tags

clean:	subdirs

install:	subdirs

