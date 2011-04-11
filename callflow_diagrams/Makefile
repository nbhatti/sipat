include ../Makefile.defs

NAME=cf

.PHONY:	dummy clean proper

dummy:
		@echo "relaxing"

proper:	clean

clean:	dummy

install:	install-dirs
			$(install-bin) svg2png $(bin-dir)
			@cat cf2svg.sh | sed 's@XSL_PATH="."@XSL_PATH="$(share-dir)/$(NAME)\"@g' > cf2svg
			$(install-bin) cf2svg $(bin-dir)
			@rm -f cf2svg
			$(install-share) cf.xsl $(share-dir)/${NAME}

install-dirs:	$(bin-dir) $(share-dir)/$(NAME)

$(bin-dir):	
			mkdir -p $(bin-dir)

$(share-dir)/$(NAME):	
			mkdir -p $(share-dir)/$(NAME)
			
