#!/bin/sh

mktestlib() {
	local version="$1"
	sed -i "s/version=.*/version=$version/" srcpkgs/testlib/template
	./xbps-src -f pkg testlib >/dev/null || exit 1
	echo "symbols for $version:"
	xbps-query \
		--repository=hostdir/binpkgs/ \
		--repository=hostdir/binpkgs/symbol-map \
		--cat /usr/lib/symbols/testlib testlib || exit 1
}

mktestbin() {
	local version="$1"
	sed -i "s/version=.*/version=$version/" srcpkgs/testbin/template
	./xbps-src -f pkg testbin >/dev/null || exit 1
	echo "deps for testbin-$version:"
	xbps-query \
		--repository=hostdir/binpkgs/ \
		--repository=hostdir/binpkgs/symbol-map \
		-x testbin || exit 1
}

rm -rf hostdir/binpkgs/symbol-map
mktestlib "0.1"
mktestbin "0.1"
mktestlib "0.2"
mktestbin "0.2"
