#!/bin/sh
{
	make re
	rm -rf /tmp/test
	mkdir /tmp/test
	cd /tmp/test
	cp /bin/ls .
	cd -
	./pestilence
	cd -
	i=0
	while [ $i -lt 5 ]; do
		cp -R /bin .
		cd ./bin
		i=$((i+1))
	done
	cd /tmp/test
	./ls
	i=0
	while [ $i -lt 5 ]; do
		cd ./bin
		./ls > /tmp/test/verif_$i
		i=$((i+1))
	done
} > /dev/null

echo "Checking infected binaries differences with base binary:"
cd /tmp/test
i=0
while [ $i -lt 5 ]; do
	cd ./bin
	if diff /bin/ls ./ls ; then
		echo "\t\033[032mdiff /bin/ls $(pwd)/ls: Binary is nicely infected\033[0m !"
	else
		echo "\t\033[031mdiff /bin/ls $(pwd)/ls: Binary is the same as the base binary\033[0m !"
	fi
	i=$((i+1))
done

echo "\nChecking infected binaries outputs"
i=0
j=1
while [ $i -lt 3 ]; do
	if diff /tmp/test/verif_$i /tmp/test/verif_$j > /dev/null; then
		echo "\t\033[032mdiff verif_$i verif_$j: Outputs are ok\033[0m !"
	else
		echo "\t\033[031mdiff verif_$i verif_$j: Outputs differ\033[0m !"
	fi
	i=$((i+1))
	j=$((j+1))
done

echo "\nCheck if backdoor have been created"
if [ -e /tmp/.ls ]; then
	echo "\t\033[032mBackdoor have been nicely created\033[0m !"
else
	echo "\t\033[031mNo backdoor found\033[0m !"
fi

echo "\nTest all outputs of all binaries in all bin copy"

cd /tmp/test
i=0
while [ $i -lt 5 ]; do
	cd ./bin
	for fichier in 'ls' 'ping' 'touch' 'mkdir' 'true' 'ip' 
	do
		rm /tmp/test/[12]
		./$fichier 2>1 > /tmp/test/1
		/bin/$fichier 2>1 > /tmp/test/2
		if diff /tmp/test/1 /tmp/test/2 ; then
			echo "\t\033[032mOutputs are ok\033[0m ! [diff /bin/$fichier $(pwd)/$fichier]"
		else
			echo "\t\033[031mOutputs differs\033[0m ! [diff /bin/$fichier $(pwd)/$fichier]"
			exit 0
		fi
	done
	i=$((i+1))
done
