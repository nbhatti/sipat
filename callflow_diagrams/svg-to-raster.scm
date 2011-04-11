(define (svg-to-raster infile
		       outfile
		       resolution
		       xmax
		       ymax)
  (let* ((image (car (file-svg-load 
		      RUN-NONINTERACTIVE 
		      infile 
		      "" 
		      resolution 
		      (- 0 xmax) 
		      (- 0 ymax) 
		      0
		      )
		     )
		)
	 (drawable (car (gimp-image-get-active-layer image))))
    (plug-in-autocrop RUN-NONINTERACTIVE image drawable)

	; Creates a new layer, gives it a name, and adds new layer to the image
	(set! bkg-layer (car (gimp-layer-copy drawable 0)))
	(gimp-layer-set-name bkg-layer "bkg")
	(gimp-drawable-fill bkg-layer 2)
	(gimp-image-add-layer image bkg-layer 1)

	(let* (
		(lays (car (gimp-image-merge-down image drawable 0))))
		(gimp-file-save RUN-NONINTERACTIVE image lays outfile outfile)
;	 (lays (car (gimp-image-get-layers image))))
;    (gimp-file-save RUN-INTERACTIVE image lays outfile outfile)
		(gimp-image-delete image)
    ))
  )
