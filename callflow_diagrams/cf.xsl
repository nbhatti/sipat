<?xml version="1.0" encoding="UTF-8" standalone="no" ?>

<!-- 

Copyright (C) 2005-2010 Tekelec

This file is part of SIP-A&T, set of tools for SIP analysis and testing.

SIP-A&T is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version

SIP-A&T is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

-->

<xsl:stylesheet version="1.0" 
	xmlns="http://www.w3.org/2000/svg" 
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:fo="http://www.w3.org/1999/XSL/Format"
	>
<xsl:output method="xml"/>
<xsl:variable name="object_line_width" select="0.5"/>
<xsl:variable name="object_y" select="7"/>
<xsl:variable name="object_font_size" select="4"/>
<xsl:variable name="object_line_y" select="10"/>

<xsl:variable name="arrow_line_width" select="1"/>

<!-- font size of call description -->
<xsl:variable name="call_font_size" select="3"/>
<xsl:variable name="font_family">arial</xsl:variable>
<xsl:variable name="text_dy" select="-1"/>

<!-- distance between description and the call line 
(how far is the text above the line) -->
<xsl:variable name="call_text_dy" select="1"/>
<!-- -->
<xsl:variable name="call_text_dx" select="5"/>
<!-- thickness of call line -->
<xsl:variable name="call_line_width" select="0.5"/>

<xsl:variable name="space_per_call" select="10"/>
<xsl:variable name="first_call_y" select="$object_line_y + $space_per_call"/>

<!-- distance between the top of rectangle and incomming/outgoing call line -->
<xsl:variable name="synccall_dy" select="2"/>
<!-- width and height of rectangle on synchronously called object axis -->
<xsl:variable name="synccall_width" select="7"/>
<xsl:variable name="synccall_height" select="10"/>
<xsl:variable name="space_per_synccall" select="15"/>

<xsl:variable name="selfcall_width" select="10"/>
<xsl:variable name="selfcall_height" select="10"/>
<xsl:variable name="space_per_selfcall" select="20"/>

<xsl:variable name="space_per_selfsynccall" select="15"/>

<xsl:variable name="seq_appendix" select="'. '"/>

<xsl:template name="process_call">
	<xsl:param name="seq"/>
	<xsl:param name="act_y"/>
	<xsl:variable name="delta">
		<xsl:choose>
			<xsl:when test="@dst and @sync and (@dst != @src)">
				<xsl:value-of select="$space_per_synccall"/>
			</xsl:when>
			<xsl:when test="@dst and not(@sync) and (@dst != @src)">
				<xsl:value-of select="$space_per_call"/>
			</xsl:when>
			<xsl:when test="(not(@dst) or (@dst = @src)) and @sync">
				<xsl:value-of select="$space_per_selfsynccall"/>
			</xsl:when>
			<xsl:otherwise>
				<xsl:value-of select="$space_per_selfcall"/>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:variable>
	<xsl:variable name="color">
		<xsl:choose>
			<xsl:when test="@color">
				<xsl:value-of select="@color"/>
			</xsl:when>
			<xsl:otherwise>
				<xsl:value-of select="'black'"/>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:variable>
	<xsl:variable name="line-type">
		<xsl:choose>
			<xsl:when test="@line-type">
				<xsl:value-of select="@line-type"/>
			</xsl:when>
			<xsl:otherwise>
				<xsl:value-of select="'10,0'"/>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:variable>

	<xsl:choose>
		<xsl:when test="@dst and @sync and (@dst != @src)">
			<xsl:call-template name="synccalltmp">
				<xsl:with-param name="act_y" select="$act_y"/>
				<xsl:with-param name="color" select="$color"/>
				<xsl:with-param name="line-type" select="$line-type"/>
				<xsl:with-param name="seq" select="$seq"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:when test="@dst and not(@sync) and (@dst != @src)">
			<xsl:call-template name="calltmp">
				<xsl:with-param name="act_y" select="$act_y"/>
				<xsl:with-param name="color" select="$color"/>
				<xsl:with-param name="line-type" select="$line-type"/>
				<xsl:with-param name="seq" select="$seq"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:when test="(not(@dst) or (@dst = @src)) and @sync ">
			<xsl:call-template name="selfsynccalltmp">
				<xsl:with-param name="act_y" select="$act_y"/>
				<xsl:with-param name="color" select="$color"/>
				<xsl:with-param name="line-type" select="$line-type"/>
				<xsl:with-param name="seq" select="$seq"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:otherwise>
			<xsl:call-template name="selfcalltmp">
				<xsl:with-param name="act_y" select="$act_y"/>
				<xsl:with-param name="color" select="$color"/>
				<xsl:with-param name="line-type" select="$line-type"/>
				<xsl:with-param name="seq" select="$seq"/>
			</xsl:call-template>
		</xsl:otherwise>
	</xsl:choose>

	<xsl:variable name="next_call" 
		select="(following-sibling::call | following-sibling::selfcall)[1]"/>
	<xsl:for-each select="$next_call">
		<xsl:call-template name="process_call">
			<xsl:with-param name="act_y" select="$act_y + $delta"/>
			<xsl:with-param name="seq" select="$seq + 1"/>
		</xsl:call-template>
	</xsl:for-each>

	<xsl:if test="not($next_call)">
		<!-- at the end -->
		
		<!-- warning if height/width cuts the image -->
		<xsl:if test="//flow/@height &lt; $act_y">
			<xsl:message>WARNING: The image height is too small to fit the diagram!</xsl:message>
			<xsl:message>requested: <xsl:value-of select="$act_y"/></xsl:message>
			<xsl:message>height: <xsl:value-of select="//flow/@height"/></xsl:message>
		</xsl:if>
	
		<xsl:for-each select="//objects/object">
			<xsl:call-template name="objtmp">
				<xsl:with-param name="act_y" select="$act_y"/>
			</xsl:call-template>
		</xsl:for-each>
	</xsl:if>
</xsl:template>

<xsl:template name="create_marker">
	<xsl:param name="color"/>
	<xsl:text>&#x09;&#x09;</xsl:text>
	<marker id="arrow-{$color}"
		viewBox="0 0 15 10" refX="15" refY="5" 
		markerUnits="userSpaceOnUse"
		markerWidth="4" markerHeight="3"
		orient="auto">
		<g stroke="{$color}" stroke-width="{$arrow_line_width}"> 
			<line x1="15" y1="5" x2="0" y2="0"/>
			<line x1="15" y1="5" x2="0" y2="10"/>
		</g>
	</marker>
	<xsl:text>&#xA;</xsl:text>
</xsl:template>

<xsl:template name="colors">
	<xsl:param name="colorset"/>
	<xsl:if test="$colorset[1]/@color">
		<xsl:call-template name="create_marker">
			<xsl:with-param name="color" select="$colorset[1]/@color"/>
		</xsl:call-template>
	</xsl:if>
	
	<xsl:variable name="next" select="$colorset[@color != $colorset[1]/@color]"/>
	<xsl:if test="$next">
		<xsl:call-template name="colors">
			<xsl:with-param name="colorset" select="$next"/>
		</xsl:call-template>
	</xsl:if>
</xsl:template>

<xsl:template match="//flow">
<svg width="{@width}mm" height="{@height}mm" viewBox="0 0 {@width * @scale} {@height * @scale}"
     version="1.1">
	<xsl:text>&#xA;&#x09;</xsl:text>
	<defs>
	<xsl:text>&#xA;</xsl:text>
		<!-- create markers for all used colors - it is really not possible
		to give the color to marker as parameter? -->
		<xsl:call-template name="create_marker">
			<xsl:with-param name="color" select="'black'"/>
		</xsl:call-template>
		<xsl:variable name="colorset" select="(call |selfcall)[@color != 'black']"/>
		<xsl:call-template name="colors">
			<xsl:with-param name="colorset" select="$colorset"/>
		</xsl:call-template>
	<xsl:text>&#x09;</xsl:text>
	</defs>
	<xsl:text>&#xA;</xsl:text>

<!--
	<rect x="0" y="0" width="{@width}" height="{@height}"
		fill="white" stroke="none" />
-->

<!--	<xsl:for-each select="objects/object">
		<xsl:call-template name="objtmp"/>
	</xsl:for-each>-->

	<!-- Process first call/selfcall element -->
	<xsl:variable name="first_call" select="(call|selfcall)[1]"/>
	
	<xsl:for-each select="$first_call">
		<xsl:call-template name="process_call">
			<xsl:with-param name="act_y" select="$first_call_y"/>
			<xsl:with-param name="seq" select="1"/>
		</xsl:call-template>
	</xsl:for-each>
</svg>
</xsl:template>

<!-- object lines -->
<xsl:template match="//objects/object" name="objtmp">
	<xsl:param name="act_y"/>
	<xsl:text>&#x09;</xsl:text>
	<xsl:variable name="yy" select="$act_y"/>
    <line x1="{@x}" y1="{$object_line_y}" x2="{@x}" y2="{$object_line_y + $yy}"
		stroke="black" stroke-width="{$object_line_width}" stroke-dasharray="5,2"/>
	<xsl:text>&#xA;&#x09;</xsl:text>
	<text stroke="none" x="{@x}" y="{$object_y}" text-anchor="middle" 
		font-size="{$object_font_size}"><xsl:value-of select="@desc"/></text>
	<xsl:text>&#xA;</xsl:text>

</xsl:template>

<!-- calls -->
<xsl:template match="call" name="calltmp">
	<xsl:param name="act_y"/>
	<xsl:param name="color"/>
	<xsl:param name="line-type"/>
	<xsl:param name="seq"/>
	<xsl:variable name="yy" select="$act_y"/>
	<xsl:variable name="srcx" select="@src"/>
	<xsl:variable name="dstx" select="@dst"/>
	<xsl:variable name="xx" select="//objects/object[@name=$srcx]/@x"/>
	<xsl:variable name="xx1" select="//objects/object[@name=$dstx]/@x"/>
	<xsl:variable name="textx">
		<xsl:choose>
			<xsl:when test="$xx &lt; $xx1">
				<xsl:value-of select="$xx"/>
			</xsl:when>
			<xsl:otherwise>
				<xsl:value-of select="$xx1"/>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:variable>
	<xsl:text>&#x09;</xsl:text>
	<line x1="{$xx}" y1="{$yy}" x2="{$xx1}" y2="{$yy}"
		marker-end="url(#arrow-{$color})" 
		stroke="{$color}" stroke-width="{$call_line_width}" stroke-dasharray="{$line-type}"/>
	<xsl:text>&#x0A;&#x09;</xsl:text>
	<text stroke="none" x="{$textx + $call_text_dx}" y="{$yy - $call_text_dy}" 
		dy="{$text_dy}"
		letter-spacing="0" word-spacing="0" kerning="0"
		font-family="{$font_family}"
		font-size="{$call_font_size}">
			<xsl:value-of select="$seq"/>
			<xsl:value-of select="$seq_appendix"/>
			<xsl:value-of select="@desc"/>
	</text>
	<xsl:text>&#x0A;</xsl:text>
</xsl:template>

<!-- selfcalls -->
<xsl:template match="selfcall" name="selfcalltmp">
	<xsl:param name="act_y"/>
	<xsl:param name="color"/>
	<xsl:param name="line-type"/>
	<xsl:param name="seq"/>
	<xsl:variable name="yy" select="$act_y"/>
	<xsl:variable name="srcx" select="@src"/>
	<xsl:variable name="xx" select="//objects/object[@name=$srcx]/@x"/>
	<xsl:variable name="xx1" select="$xx + $selfcall_width"/>
	<xsl:variable name="yy1" select="$yy + $selfcall_height"/>
	<xsl:variable name="textx" select="$xx"/>
	<xsl:text>&#x09;</xsl:text>
    <polyline fill="none" 
			points="{$xx},{$yy} {$xx1},{$yy} {$xx1},{$yy1} {$xx},{$yy1}"
			stroke="{$color}" stroke-width="{$call_line_width}" stroke-dasharray="{$line-type}"
            marker-end="url(#arrow-{$color})" />
	<xsl:text>&#x0A;&#x09;</xsl:text>
	<text stroke="none" x="{$textx + $call_text_dx}" y="{$yy - $call_text_dy}" 
		dy="{$text_dy}"
		letter-spacing="0" word-spacing="0" kerning="0"
		font-family="{$font_family}"
		font-size="{$call_font_size}">
			<xsl:value-of select="$seq"/>
			<xsl:value-of select="$seq_appendix"/>
			<xsl:value-of select="@desc"/>
	</text>
	<xsl:text>&#x09;</xsl:text>
</xsl:template>

<!-- self sync calls -->
<xsl:template name="selfsynccalltmp">
	<xsl:param name="act_y"/>
	<xsl:param name="color"/>
	<xsl:param name="line-type"/>
	<xsl:param name="seq"/>
	<xsl:variable name="yy" select="$act_y"/>
	<xsl:variable name="srcx" select="@src"/>
	<xsl:variable name="xx" select="//objects/object[@name=$srcx]/@x"/>
	<xsl:variable name="xx1" select="$xx + $selfcall_width"/>
	<xsl:variable name="yy1" select="$yy + $selfcall_height - 2 * $synccall_dy"/>
	<xsl:variable name="textx" select="$xx"/>
	<xsl:variable name="dx" select="$synccall_width * 0.5"/>
	<xsl:text>&#x09;</xsl:text>
    <polyline fill="none" 
			points="{$xx + $dx},{$yy} {$xx1},{$yy} {$xx1},{$yy1} {$xx + $dx},{$yy1}"
			stroke="{$color}" stroke-width="{$call_line_width}" stroke-dasharray="{$line-type}"
            marker-end="url(#arrow-{$color})" />
	<xsl:text>&#x0A;&#x09;</xsl:text>
	<rect x="{$xx - $dx}" y="{$yy - $synccall_dy}" 
		width="{2 * $dx}" height="{$synccall_height}"
        fill="white" stroke="{$color}" stroke-width="{$call_line_width}" />
	<xsl:text>&#x0A;&#x09;</xsl:text>
	<text stroke="none" x="{$textx + $call_text_dx}" y="{$yy - $call_text_dy}" 
		dy="{$text_dy}"
		letter-spacing="0" word-spacing="0" kerning="0"
		font-family="{$font_family}"
		font-size="{$call_font_size}">
			<xsl:value-of select="$seq"/>
			<xsl:value-of select="$seq_appendix"/>
			<xsl:value-of select="@desc"/>
	</text>
	<xsl:text>&#x09;</xsl:text>
</xsl:template>

<!-- synccalls -->
<xsl:template match="synccall" name="synccalltmp">
	<xsl:param name="act_y"/>
	<xsl:param name="color"/>
	<xsl:param name="line-type"/>
	<xsl:param name="seq"/>
	<xsl:variable name="yy" select="$act_y"/>
	<xsl:variable name="srcx" select="@src"/>
	<xsl:variable name="dstx" select="@dst"/>
	<xsl:variable name="xx" select="//objects/object[@name=$srcx]/@x"/>
	<xsl:variable name="xx1" select="//objects/object[@name=$dstx]/@x"/>
	<xsl:variable name="textx">
		<xsl:choose>
			<xsl:when test="$xx &lt; $xx1">
				<xsl:value-of select="$xx"/>
			</xsl:when>
			<xsl:otherwise>
				<xsl:value-of select="$xx1"/>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:variable>
	<xsl:variable name="dx" select="$synccall_width * 0.5"/>
	<xsl:text>&#x09;</xsl:text>
    <line x1="{$xx}" y1="{$yy}" x2="{$xx1 - $dx}" y2="{$yy}"
            marker-end="url(#arrow-{$color})" 
			stroke="{$color}" stroke-width="{$call_line_width}" stroke-dasharray="{$line-type}"/>
	<xsl:text>&#x0A;&#x09;</xsl:text>
	<rect x="{$xx1 - $dx}" y="{$yy - $synccall_dy}" 
		width="{2 * $dx}" height="{$synccall_height}"
        fill="white" stroke="{$color}" stroke-width="{$call_line_width}" />
	<xsl:text>&#x0A;&#x09;</xsl:text>
    <line x1="{$xx1 - $dx}" y1="{$yy + $synccall_height - 2 * $synccall_dy}" 
		x2="{$xx}" y2="{$yy + $synccall_height - 2 * $synccall_dy}" 
		stroke-dasharray="2,2" marker-end="url(#arrow-{$color})" 
		stroke="{$color}" stroke-width="{$call_line_width}" />
	<xsl:text>&#x0A;&#x09;</xsl:text>
	<text stroke="none" x="{$textx + $call_text_dx}" y="{$yy - $call_text_dy}" 
		dy="{$text_dy}"
		letter-spacing="0" word-spacing="0" kerning="0"
		font-family="{$font_family}"
		font-size="{$call_font_size}">
			<xsl:value-of select="$seq"/>
			<xsl:value-of select="$seq_appendix"/>
			<xsl:value-of select="@desc"/>
	</text>
	<xsl:text>&#x0A;</xsl:text>
</xsl:template>


</xsl:stylesheet>
