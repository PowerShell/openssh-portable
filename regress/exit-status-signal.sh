# This test performs validation that ssh client is not successive on being terminated

tid="exit status on signal"

# spawn client in background
rm -f $OBJ/remote_pid
${SSH} -F $OBJ/ssh_proxy somehost 'echo $$ >'$OBJ'/remote_pid; sleep 444' &
ssh_pid=$!

# wait for it to start
n=20
while [ ! -f $OBJ/remote_pid ] && [ $n -gt 0 ]; do
	n=$(($n - 1))
	echo "sleep for 1 sec"
	sleep 1
done

kill $ssh_pid
wait $ssh_pid
exit_code=$?

if [ $exit_code -eq 0 ]; then
	fail "ssh client should fail on signal"
fi

if [ "$os" == "windows" ]; then
	powershell.exe /c "stop-process -name sleep" >/dev/null 2>&1
fi