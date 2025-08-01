#!/bin/bash

SMBCLIENT_CMD="smbclient -U alberic --password=quetmen '\\\\127.0.0.1\\database' "

function usage() {
	echo "Test script for Tracim Samba VFS module."
	echo "Usage: $0 [cd|get|put|rm|all|--help]"
	echo "  all   - Run all tests"
	echo "  cd    - Change directory to user_alberic and list contents"
	echo "  get   - Get test.txt from user_alberic directory"
	echo "  put   - Put toto.txt into the current directory"
	echo "  rm    - Remove test.txt from user_alberic directory"
	echo " If no command is given, it runs the simple smbclient interactively."
}

function run() {
	cmd="$1"
	echo " - test '$cmd'"
	echo > test.log
	TEST_CMD="$SMBCLIENT_CMD -c >test.log 2>&1"
	case $cmd in
		--help)
			usage
			exit 0
			;;
		cd)
			eval $TEST_CMD <<EOF
cd user_alberic
ls 
EOF
			;;
		get)
			eval $TEST_CMD <<EOF
cd user_alberic
get test.txt
EOF
			;;
		put)
			eval $TEST_CMD <<EOF
put toto.txt
EOF
			;;
		rm)
			eval $TEST_CMD <<EOF
cd user_alberic
rm test.txt 
EOF
			;;
		rename)
			eval $TEST_CMD <<EOF
cd user_alberic
rename test.txt test2.txt
EOF
			;;
		all)
			run cd
			run get
			run put
			run rm
			run rename
			;;
		*)
			echo "NT_STATUS_UNKNOWN_TEST : Unknown command '$cmd'" >test.log
	esac
	grep "NT_STATUS_" test.log >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		echo -e "\n -> Error found in test '$cmd' : \n"
		cat test.log
		exit 1
	fi
}

if [ $# -eq 0 ]; then
	eval $SMBCLIENT_CMD
else
	run $*
fi
