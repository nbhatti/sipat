(define (svg2png infile outfile resolution)
(let* (;(img (car (gimp-image-new xmax ymax RGB)))
       (img (car (file-svg-load RUN-NONINTERACTIVE infile "" resolution 0 0 0 )))
       (drawable (car (gimp-layer-new img 100 100 RGB-IMAGE "bkg" 100 NORMAL)))
;       (old-fg (car (gimp-palette-get-foreground)))
;       (old-bg (car (gimp-palette-get-background)))
;       (layer (car (gimp-image-active-drawable img)))
		(bkcolor (list 250 0 250))
      )

    ;vse provedeme v jednom kroku (pujde vratit jednim klikem na undo
;    (gimp-image-undo-disable img)
    
    ;pridame novy layer do naseho noveho obrazku do urovne 0 (background)
    (gimp-image-add-layer img drawable 0)
	(gimp-image-lower-layer img drawable)
	(gimp-layer-resize-to-image-size drawable)
    
    ;nastavime barvu pozadi
;    (gimp-palette-set-background bkcolor)
    
    ;layer vyplnime barvou
    (gimp-edit-fill drawable WHITE-FILL)
    
    ;\rusime selekci
    (gimp-selection-none img)

    ;vratime nastaveni palety na puvodni hodnoty
 ;   (gimp-palette-set-background old-bg)
;    (gimp-palette-set-foreground old-fg)
    
    ;opet zapneme undo logovani
;    (gimp-image-undo-enable img)
    
    ;zobrazime novy obrazek
;    (gimp-display-new img))    	         	   			   

;    (plug-in-autocrop RUN-NONINTERACTIVE img drawable)
    ;(gimp-file-save RUN-NONINTERACTIVE img drawable outfile outfile)
	(let* (
	   (layer-to-save (car (gimp-image-merge-visible-layers img 0))))
	    (gimp-file-save RUN-NONINTERACTIVE img layer-to-save outfile outfile)
	)
    (gimp-image-delete img)
	(gimp-quit 0)
)
)
