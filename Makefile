run:
	nim c --outdir:build --run main.nim

build_dev:
	nim c --outdir:build main.nim

build_release:
	nim c --outdir:build --passc:-flto -d:release main.nim

update_consts:
	cd consts && nim c detect.nim && ./detect && rm detect && rm genconsts.c && rm genconsts && rm testh
