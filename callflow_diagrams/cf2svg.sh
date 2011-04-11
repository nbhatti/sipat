#!/bin/bash

if [[ "x$2" == "x" ]] ; then
	echo "$0 <input_flow.xml> <output.svg>"
	exit 1
fi

XSL_PATH="."
XSLTPROC="xsltproc"
XSLT="${XSL_PATH}/cf.xsl"

${XSLTPROC} --xinclude -o "$2" "$XSLT" "$1"
