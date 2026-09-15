#	$OpenBSD: proxyjump.sh,v 1.1 2026/03/30 07:19:02 djm Exp $
#	Placed in the Public Domain.

tid="proxyjump"

# Parsing tests
verbose "basic parsing"
for jspec in \
	"jump1" \
	"user@jump1" \
	"jump1:2222" \
	"user@jump1:2222" \
	"jump1,jump2" \
	"user1@jump1:2221,user2@jump2:2222" \
	"ssh://user@host:2223" \
	; do
	case "$jspec" in
	"jump1")		expected="jump1" ;;
	"user@jump1")		expected="user@jump1" ;;
	"jump1:2222")		expected="jump1:2222" ;;
	"user@jump1:2222")	expected="user@jump1:2222" ;;
	"jump1,jump2")		expected="jump1,jump2" ;;
	"user1@jump1:2221,user2@jump2:2222")
		expected="user1@jump1:2221,user2@jump2:2222" ;;
	"ssh://user@host:2223")	expected="user@host:2223" ;;
	esac
	if [ "$os" == "windows" ]; then
		# Windows ssh emits CRLF; strip CR before comparing
		f=`${SSH} -GF /dev/null -oProxyJump="$jspec" somehost | \
			awk '/^proxyjump /{print $2}' | tr -d '\r'`
	else
		f=`${SSH} -GF /dev/null -oProxyJump="$jspec" somehost | \
			awk '/^proxyjump /{print $2}'`
	fi
	if [ "$f" != "$expected" ]; then
		fail "ProxyJump $jspec: expected $expected, got $f"
	fi
	if [ "$os" == "windows" ]; then
		# Windows ssh emits CRLF; strip CR before comparing
		f=`${SSH} -GF /dev/null -J "$jspec" somehost | \
			awk '/^proxyjump /{print $2}' | tr -d '\r'`
	else
		f=`${SSH} -GF /dev/null -J "$jspec" somehost | \
			awk '/^proxyjump /{print $2}'`
	fi
	if [ "$f" != "$expected" ]; then
		fail "ssh -J $jspec: expected $expected, got $f"
	fi
done

verbose "precedence"
f=`${SSH} -GF /dev/null -oProxyJump=none -oProxyJump=jump1 somehost | \
	grep "^proxyjump "`
if [ -n "$f" ]; then
	fail "ProxyJump=none first did not win"
fi
if [ "$os" == "windows" ]; then
	# Windows ssh emits CRLF; strip CR before comparing
	f=`${SSH} -GF /dev/null -oProxyJump=jump -oProxyCommand=foo somehost | \
		grep "^proxyjump " | tr -d '\r'`
else
	f=`${SSH} -GF /dev/null -oProxyJump=jump -oProxyCommand=foo somehost | \
		grep "^proxyjump "`
fi
if [ "$f" != "proxyjump jump" ]; then
	fail "ProxyJump first did not win over ProxyCommand"
fi
if [ "$os" == "windows" ]; then
	# Windows ssh emits CRLF; strip CR before comparing
	f=`${SSH} -GF /dev/null -oProxyCommand=foo -oProxyJump=jump somehost | \
		grep "^proxycommand " | tr -d '\r'`
else
	f=`${SSH} -GF /dev/null -oProxyCommand=foo -oProxyJump=jump somehost | \
		grep "^proxycommand "`
fi
if [ "$f" != "proxycommand foo" ]; then
	fail "ProxyCommand first did not win over ProxyJump"
fi

verbose "command-line -J invalid characters"
cp $OBJ/ssh_config $OBJ/ssh_config.orig
for jspec in \
	"host;with;semicolon" \
	"host'with'quote" \
	"host\`with\`backtick" \
	"host\$with\$dollar" \
	"host(with)brace" \
	"user;with;semicolon@host" \
	"user'with'quote@host" \
	"user\`with\`backtick@host" \
	"user(with)brace@host" ; do
	${SSH} -GF /dev/null -J "$jspec" somehost >/dev/null 2>&1
	if [ $? -ne 255 ]; then
		fail "ssh -J \"$jspec\" was not rejected"
	fi
	${SSH} -GF /dev/null -oProxyJump="$jspec" somehost >/dev/null 2>&1
	if [ $? -ne 255 ]; then
		fail "ssh -oProxyJump=\"$jspec\" was not rejected"
	fi
done
# Special characters should be accepted in the config though.
echo "ProxyJump user;with;semicolon@host;with;semicolon" >> $OBJ/ssh_config
if [ "$os" == "windows" ]; then
	# Windows ssh emits CRLF; strip CR before comparing
	f=`${SSH} -GF $OBJ/ssh_config somehost | grep "^proxyjump " | tr -d '\r'`
else
	f=`${SSH} -GF $OBJ/ssh_config somehost | grep "^proxyjump "`
fi
if [ "$f" != "proxyjump user;with;semicolon@host;with;semicolon" ]; then
	fail "ProxyJump did not allow special characters in config: $f"
fi

verbose "functional test"
# Use different names to avoid the loop detection in ssh.c
grep -iv HostKeyAlias $OBJ/ssh_config.orig > $OBJ/ssh_config
cat << _EOF >> $OBJ/ssh_config
Host jump-host
	HostkeyAlias jump-host
Host target-host
	HostkeyAlias target-host
_EOF
cp $OBJ/known_hosts $OBJ/known_hosts.orig
sed 's/^[^ ]* /jump-host /' < $OBJ/known_hosts.orig > $OBJ/known_hosts
sed 's/^[^ ]* /target-host /' < $OBJ/known_hosts.orig >> $OBJ/known_hosts
start_sshd

verbose "functional ProxyJump"
if [ "$os" == "windows" ]; then
	# Windows ssh emits CRLF; strip CR before comparing
	res=`${REAL_SSH} -F $OBJ/ssh_config -J jump-host target-host echo "SUCCESS" 2>/dev/null | tr -d '\r'`
else
	res=`${REAL_SSH} -F $OBJ/ssh_config -J jump-host target-host echo "SUCCESS" 2>/dev/null`
fi
if [ "$res" != "SUCCESS" ]; then
	fail "functional test failed: expected SUCCESS, got $res"
fi
