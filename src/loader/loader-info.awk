# Note: This file is included only for targets which have pokedata workaround
function hex2dec(s,    i,c,n,v) {
	 n=0
	 for (i=1; i<=length(s); i++) {
		 c=substr(s,i,1)
		 v=index("0123456789abcdef", tolower(c))-1
		 n=(n*16)+v
	 }
	 return n
}
/\ypokedata_workaround\y/{pokedata_workaround=hex2dec($2)}
/\y_start\y/{start=hex2dec($2)}
END {
	print "#include <unistd.h>"
	print "const ssize_t offset_to_pokedata_workaround=" (pokedata_workaround-start) ";"
}
