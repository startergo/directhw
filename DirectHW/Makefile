#
# DirectHW - Kernel extension to pass through IO commands to user space
#
# Copyright © 2008-2010 coresystems GmbH <info@coresystems.de>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

all: main libs

is11   := $(shell bc <<< "$${OSTYPE\#darwin} == 20")
is10_15 := $(shell bc <<< "$${OSTYPE\#darwin} == 19")
is10_14 := $(shell bc <<< "$${OSTYPE\#darwin} == 18")
is10_13 := $(shell bc <<< "$${OSTYPE\#darwin} == 17")
is10_12 := $(shell bc <<< "$${OSTYPE\#darwin} == 16")
is10_11 := $(shell bc <<< "$${OSTYPE\#darwin} == 15")
is10_10 := $(shell bc <<< "$${OSTYPE\#darwin} == 14")
is10_9 := $(shell bc <<< "$${OSTYPE\#darwin} == 13")
is10_9plus := $(shell bc <<< "$${OSTYPE\#darwin} >= 13")
is10_8 := $(shell bc <<< "$${OSTYPE\#darwin} == 12")
is10_7 := $(shell bc <<< "$${OSTYPE\#darwin} == 11")
is10_6 := $(shell bc <<< "$${OSTYPE\#darwin} == 10")
is10_5 := $(shell bc <<< "$${OSTYPE\#darwin} == 9")
is10_4 := $(shell bc <<< "$${OSTYPE\#darwin} == 8")
# Note: Do not append comments to makefile := assignment lines because spaces before the # become part of the assigned string.

# latestsdk := $(shell xcodebuild -showsdks | sort -r | sed -nE '/.*(-sdk macosx.*)/ { s//\1/;p;q; }')

proj := DirectHW.xcodeproj
build := build/buildlatest
extensions := /System/Library/Extensions
debugsym :=
sdk := -sdk macosx
deploy := MACOSX_DEPLOYMENT_TARGET=10.6
arch := 
ifeq ($(is11), 1)
	build := build/build11
endif
ifeq ($(is10_15), 1)
	build := build/build10.15
endif
ifeq ($(is10_14), 1)
	build := build/build10.14
endif
ifeq ($(is10_13), 1)
	proj := DirectHW.xcodeproj
	build := build/build10.13
	sdk := -sdk macosx10.13
	arch := -arch x86_64
endif
ifeq ($(is10_12), 1)
	proj := DirectHW10.6.xcodeproj
	build := build/build10.12
	sdk := 
	deploy := 
endif
ifeq ($(is10_11), 1)
	proj := DirectHW10.6.xcodeproj
	build := build/build10.11
	sdk := 
	deploy := 
endif
ifeq ($(is10_10), 1)
	proj := DirectHW10.6.xcodeproj
	build := build/build10.10
	sdk := 
	deploy := 
endif
ifeq ($(is10_9), 1)
	proj := DirectHW10.6.xcodeproj
	build := build/build10.9
	sdk := 
	deploy := 
endif
ifeq ($(is10_9plus), 1)
	extensions := /Library/Extensions
endif
ifeq ($(is10_8), 1)
	proj := DirectHW10.6.xcodeproj
	build := build/build10.8
	sdk := 
	deploy := 
endif
ifeq ($(is10_7), 1)
	proj := DirectHW10.6.xcodeproj
	build := build/build10.7
	sdk := 
	deploy := 
endif
ifeq ($(is10_6), 1)
	proj := DirectHW10.6.xcodeproj
	build := build/build10.6
	sdk := 
	deploy := 
endif
ifeq ($(is10_5), 1)
	proj := DirectHW10.5.xcodeproj
	build := build/build10.5
	debugsym := -g
	sdk := 
	deploy := 
endif
ifeq ($(is10_4), 1)
	proj := DirectHW10.4.xcodeproj
	build := build/build10.4
	sdk := 
	deploy := 
endif

main:
	xcodebuild -alltargets -project $(proj) $(sdk) $(deploy) $(arch) SYMROOT=$(build)

libs: DirectHW.c DirectHW.h
	$(CC) DirectHW.c -dynamiclib -framework IOKit -o $(build)/Release/libDirectHW.dylib $(debugsym)
	#$(CC) -static -c DirectHW.c -o $(build)/Release/libDirectHW.a

install:
	sudo mkdir -p /usr/local/lib
	[[ -e $(extensions)/DirectHW.kext ]] && sudo rm -R $(extensions)/DirectHW.kext || :
	sudo cp -p -R $(build)/Release/DirectHW.kext $(extensions)/
	[[ -e /Library/Frameworks/DirectHW.framework ]] && sudo rm -R /Library/Frameworks/DirectHW.framework || :
	sudo cp -p -R $(build)/Release/DirectHW.framework /Library/Frameworks/
	sudo cp -p $(build)/Release/libDirectHW.a /usr/local/lib/
	sudo cp -p $(build)/Release/libDirectHW.dylib /usr/local/lib/
	sudo chmod -R 755 $(extensions)/DirectHW.kext
	sudo chmod -R 755 /Library/Frameworks/DirectHW.framework
	sudo chmod 644 /usr/local/lib/libDirectHW.a
	sudo chmod 644 /usr/local/lib/libDirectHW.dylib
	sudo chown -R root:wheel $(extensions)/DirectHW.kext
	sudo chown -R root:wheel /Library/Frameworks/DirectHW.framework
	sudo kextunload -v $(extensions)/DirectHW.kext || :
	sudo kextload -v $(extensions)/DirectHW.kext
	sudo touch $(extensions) || :
	command -v kmutil > /dev/null && sudo kmutil install --volume-root / --check-rebuild || :

clean:
	rm -rf $(build)
