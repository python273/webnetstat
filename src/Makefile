run:
	nim c --outdir:build --run webnetstat.nim

build_dev:
	nim c --outdir:build webnetstat.nim

build_release:
	nim c --outdir:build --passc:-flto --opt:speed -d:release webnetstat.nim

update_consts:
	cd consts && nim c detect.nim && ./detect && rm detect && rm genconsts.c && rm genconsts && rm testh
