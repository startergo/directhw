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
# Get macOS version using sw_vers for reliable detection
# sw_vers -productVersion works in 10.3+ but not 10.2 and earlier
# Fallback using perl works in 10.1 and later
macos_version := 0$(shell sw_vers -productVersion 2>/dev/null | cut -d. -f1-2 || sw_vers 2>/dev/null | perl -ne 'if (/ProductVersion:\s*(\d+(\.\d+)?)/) { print $$1 }' | cut -d. -f1-2)

# Version comparisons using proper macOS version detection
is_big_sur_or_later := $(shell echo "$(macos_version) >= 11.0" | bc -l 2>/dev/null || echo "0")
is_catalina_or_later := $(shell echo "$(macos_version) >= 10.15" | bc -l 2>/dev/null || echo "0")
is_mojave_or_later := $(shell echo "$(macos_version) >= 10.14" | bc -l 2>/dev/null || echo "0")
is_high_sierra_or_later := $(shell echo "$(macos_version) >= 10.13" | bc -l 2>/dev/null || echo "0")
is_sierra_or_later := $(shell echo "$(macos_version) >= 10.12" | bc -l 2>/dev/null || echo "0")
is_el_capitan_or_later := $(shell echo "$(macos_version) >= 10.11" | bc -l 2>/dev/null || echo "0")
is_yosemite_or_later := $(shell echo "$(macos_version) >= 10.10" | bc -l 2>/dev/null || echo "0")
is_mavericks_or_later := $(shell echo "$(macos_version) >= 10.9" | bc -l 2>/dev/null || echo "0")
is_mountain_lion_or_later := $(shell echo "$(macos_version) >= 10.8" | bc -l 2>/dev/null || echo "0")
is_lion_or_later := $(shell echo "$(macos_version) >= 10.7" | bc -l 2>/dev/null || echo "0")
is_snow_leopard_or_later := $(shell echo "$(macos_version) >= 10.6" | bc -l 2>/dev/null || echo "0")
is_leopard_or_later := $(shell echo "$(macos_version) >= 10.5" | bc -l 2>/dev/null || echo "0")
is_tiger_or_later := $(shell echo "$(macos_version) >= 10.4" | bc -l 2>/dev/null || echo "0")

# latestsdk := $(shell xcodebuild -showsdks | sort -r | sed -nE '/.*(-sdk macosx.*)/ { s//\1/;p;q; }')

proj := DirectHW.xcodeproj
build := build/buildlatest
extensions := /System/Library/Extensions
debugsym :=
sdk := -sdk macosx
deploy := MACOSX_DEPLOYMENT_TARGET=10.6
arch :=
# Use proper macOS version detection for build configuration
ifneq ($(is_big_sur_or_later), 0)
	build := build/build11
endif
ifneq ($(is_catalina_or_later), 0)
	build := build/build10.15
endif
ifneq ($(is_mojave_or_later), 0)
	build := build/build10.14
endif
ifneq ($(is_high_sierra_or_later), 0)
	proj := DirectHW.xcodeproj
	build := build/build10.13
	sdk := -sdk macosx10.13
	arch := -arch x86_64
endif
ifneq ($(is_sierra_or_later), 0)
	proj := DirectHW10.6.xcodeproj
	build := build/build10.12
	sdk :=
	deploy :=
endif
ifneq ($(is_el_capitan_or_later), 0)
	proj := DirectHW10.6.xcodeproj
	build := build/build10.11
	sdk :=
	deploy :=
endif
ifneq ($(is_yosemite_or_later), 0)
	proj := DirectHW10.6.xcodeproj
	build := build/build10.10
	sdk :=
	deploy :=
endif
ifneq ($(is_mavericks_or_later), 0)
	proj := DirectHW10.6.xcodeproj
	build := build/build10.9
	sdk :=
	deploy :=
	extensions := /Library/Extensions
endif
ifneq ($(is_mountain_lion_or_later), 0)
	proj := DirectHW10.6.xcodeproj
	build := build/build10.8
	sdk :=
	deploy :=
endif
ifneq ($(is_lion_or_later), 0)
	proj := DirectHW10.6.xcodeproj
	build := build/build10.7
	sdk :=
	deploy :=
endif
ifneq ($(is_snow_leopard_or_later), 0)
	proj := DirectHW10.6.xcodeproj
	build := build/build10.6
	sdk :=
	deploy :=
endif
ifneq ($(is_leopard_or_later), 0)
	proj := DirectHW10.5.xcodeproj
	build := build/build10.5
	debugsym := -g
	sdk :=
	deploy :=
endif
ifneq ($(is_tiger_or_later), 0)
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
	# Use kmutil for macOS 10.13+ (High Sierra and later), kextcache for older versions
	if [ "$(is_high_sierra_or_later)" != "0" ]; then \
		sudo kmutil install --volume-root / --check-rebuild || : ; \
	else \
		sudo kextcache -system-prelinked-kernel || sudo kextcache -system-cache || : ; \
	fi

clean:
	rm -rf $(build)
