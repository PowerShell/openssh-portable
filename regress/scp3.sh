#	$OpenBSD: scp3.sh,v 1.5 2023/09/08 06:10:57 djm Exp $
#	Placed in the Public Domain.

tid="scp3"

COPY2=${OBJ}/copy2
DIR=${COPY}.dd
DIR2=${COPY}.dd2

maybe_add_scp_path_to_sshd

SRC=`dirname ${SCRIPT}`
cp ${SRC}/scp-ssh-wrapper.sh ${OBJ}/scp-ssh-wrapper.scp
chmod 755 ${OBJ}/scp-ssh-wrapper.scp
export SCP # used in scp-ssh-wrapper.scp

scpclean() {
	rm -rf ${COPY} ${COPY2} ${DIR} ${DIR2}
	mkdir ${DIR} ${DIR2}
	chmod 755 ${DIR} ${DIR2}
}

# Create directory structure for recursive copy tests.
forest() {
	scpclean
	rm -rf ${DIR2}
	cp ${DATA} ${DIR}/copy
# symbolic link test coverage on Windows is in SCP.Tests.ps1
if [ "$os" != "windows" ]; then
	ln -s ${DIR}/copy ${DIR}/copy-sym
fi
	mkdir ${DIR}/subdir
	cp ${DATA} ${DIR}/subdir/copy
if [ "$os" != "windows" ]; then
	ln -s ${DIR}/subdir ${DIR}/subdir-sym
fi
}

for mode in scp sftp ; do
	tag="$tid: $mode mode"

	# scpopts should be an array to preverse the double quotes
	if [ "$os" == "windows" ]; then
		if test $mode = scp ; then
			scpopts=(-F${OBJ}/ssh_proxy -S "$TEST_SHELL_PATH ${SSH}" -q -O)
		else
			scpopts=(-s -D ${SFTPSERVER})
		fi
	else
		scpopts="-F${OBJ}/ssh_proxy -S ${SSH} -q"
		if test $mode = scp ; then
			scpopts="$scpopts -O"
		else
			scpopts="-s -D ${SFTPSERVER}"
		fi
	fi

	verbose "$tag: simple copy remote file to remote file"
	scpclean
	$SCP "${scpopts[@]}" -3 hostA:${DATA} hostB:${COPY} || fail "copy failed"
	cmp ${DATA} ${COPY} || fail "corrupted copy"

	verbose "$tag: simple copy remote file to remote dir"
	scpclean
	cp ${DATA} ${COPY}
	$SCP "${scpopts[@]}" -3 hostA:${COPY} hostB:${DIR} || fail "copy failed"
	cmp ${COPY} ${DIR}/copy || fail "corrupted copy"

	verbose "$tag: recursive remote dir to remote dir"
	forest
	$SCP "${scpopts[@]}" -3r hostA:${DIR} hostB:${DIR2} || fail "copy failed"
	diff -r ${DIR} ${DIR2} || fail "corrupted copy"
	diff -r ${DIR2} ${DIR} || fail "corrupted copy"

	verbose "$tag: detect non-directory target"
	scpclean
	echo a > ${COPY}
	echo b > ${COPY2}
	$SCP "${scpopts[@]}" -3 hostA:${DATA} hostA:${COPY} hostB:${COPY2}
	cmp ${COPY} ${COPY2} >/dev/null && fail "corrupt target"
done

scpclean
rm -f ${OBJ}/scp-ssh-wrapper.exe
