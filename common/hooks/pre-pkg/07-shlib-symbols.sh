# This hook executes the following tasks:
#	- generates shlib-provides file for xbps-create(8)

get_symbols() {
	local _destdir="$1" _fname="$2" _soname="$3"
	local _addr _type _sym
	local _path="${_fname#$_destdir}"
	_path=${_path%/*}
	$NM -Dg --defined-only $_fname | while read _addr _type _sym; do
		echo "${_path}/$_soname $_sym ${pkgname}-${version}"
		echo "${_path}/$_soname $_sym ${pkgname}-${version}" >&2
	done
}

get_old_symbols() {
	local _destdir="$1" _fname="$2"
	$XBPS_QUERY_CMD -R --cat "/usr/lib/symbols/${pkgname}" "$pkgname" || :
}

merge_symbols() {
	awk '
	{x[$1][$2]=$3}
	END{
		for (k in x) for (k1 in x[k]) printf "%s %s %s\n",k,k1,x[k][k1]
	}'
}

collect_symbols() {
	local _destdir="$1"
	local _soname

	if [ ! -d ${_destdir} ]; then
		return 0
	fi
	mkdir -p "${_destdir}/usr/lib/symbols"

	find ${_destdir} -type f -name "*.so*" | while read f; do
		_fname="${f##*/}"
		case "$(file -bi "$f")" in
		application/x-sharedlib*|application/x-pie-executable*)
			_soname=$(${OBJDUMP} -p "$f"|grep SONAME|awk '{print $2}')
			get_symbols "$_destdir" "$f" "$_soname"
			get_old_symbols "$_destdir" "$f" "$_soname"
			;;
		esac
	done | merge_symbols >"${_destdir}/usr/lib/symbols/${pkgname}"
}

hook() {
	local _destdir32=${XBPS_DESTDIR}/${pkgname}-32bit-${version}

	if [ -z "$shlib_provides" -a "${archs// /}" = "noarch" -o -n "$noshlibprovides" ]; then
		return 0
	fi

	# native pkg
	collect_symbols ${PKGDESTDIR}
	# 32bit pkg
	collect_symbols ${_destdir32}
}
