#!/bin/bash

echo -e "\e[0;32mRemoving current libraries\e[0;m"

	cd /usr/local/src/capstone/
	./make.sh uninstall

	cd /usr/local/src/keystone/build/
	make uninstall

	cd /usr/local/src/unicorn/
	./make.sh uninstall

	rm -rf /usr/local/src/capstone/
	rm -rf /usr/local/src/keystone/
	rm -rf /usr/local/src/unicorn/

echo -e "\e[0;32mCloning libraries\e[0;m"

	cd /usr/local/src/
	git clone https://github.com/aquynh/capstone.git
	git clone https://github.com/keystone-engine/keystone.git
	git clone https://github.com/unicorn-engine/unicorn.git

echo -e "\e[0;32mBuilding libraries\e[0;m"

	cd /usr/local/src/capstone/
	./make.sh
	./make.sh install

	cd /usr/local/src/keystone/
	mkdir build
	cd build
	../make-share.sh
	make install

	cd /usr/local/src/unicorn/
	./make.sh
	./make.sh install
	ln -s /usr/local/lib/libkeystone.so.0 /usr/lib/libkeystone.so.0

echo -e "\e[0;32mDone!\e[0;m"
