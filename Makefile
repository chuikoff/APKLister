# APK Lister - Total Commander Lister plugin for Android packages
# SPDX-License-Identifier: GPL-2.0-or-later
CORE = util hash inflate zip axml arsc protoxml der apksig json tables analyzer
CXXFLAGS_COMMON = -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter -Wno-misleading-indentation -DUNICODE -D_UNICODE -D__USE_MINGW_ANSI_STDIO=1
WINLIBS = -lgdi32 -luser32 -lcomctl32 -lole32 -lwindowscodecs -lmsimg32 -luuid -lshlwapi -lcomdlg32
WINLDFLAGS = -static -static-libgcc -static-libstdc++ -s

CXX32 = i686-w64-mingw32-g++
CXX64 = x86_64-w64-mingw32-g++
WINDRES32 = i686-w64-mingw32-windres
WINDRES64 = x86_64-w64-mingw32-windres

B = build
CORE_SRC = $(addprefix src/,$(addsuffix .cpp,$(CORE)))
HDRS = $(wildcard src/*.h) src/android_attrs.inc

all: $(B)/apklister.wlx $(B)/apklister.wlx64 $(B)/apkinfo.exe $(B)/apkinfo32.exe $(B)/testhost.exe $(B)/testhost32.exe

$(B):
	mkdir -p $(B)

$(B)/res32.o: src/plugin.rc src/version.h | $(B)
	$(WINDRES32) -I src src/plugin.rc -O coff -o $@
$(B)/res64.o: src/plugin.rc src/version.h | $(B)
	$(WINDRES64) -I src src/plugin.rc -O coff -o $@

$(B)/apklister.wlx: $(CORE_SRC) src/plugin.cpp src/plat_win.cpp $(B)/res32.o $(HDRS) | $(B)
	$(CXX32) $(CXXFLAGS_COMMON) -shared -o $@ $(CORE_SRC) src/plugin.cpp src/plat_win.cpp $(B)/res32.o -Wl,--kill-at $(WINLDFLAGS) $(WINLIBS)

$(B)/apklister.wlx64: $(CORE_SRC) src/plugin.cpp src/plat_win.cpp $(B)/res64.o $(HDRS) | $(B)
	$(CXX64) $(CXXFLAGS_COMMON) -shared -o $@ $(CORE_SRC) src/plugin.cpp src/plat_win.cpp $(B)/res64.o $(WINLDFLAGS) $(WINLIBS)

$(B)/apkinfo.exe: $(CORE_SRC) src/apkinfo.cpp src/plat_win.cpp $(HDRS) | $(B)
	$(CXX64) $(CXXFLAGS_COMMON) -municode -o $@ $(CORE_SRC) src/apkinfo.cpp src/plat_win.cpp $(WINLDFLAGS)

$(B)/apkinfo32.exe: $(CORE_SRC) src/apkinfo.cpp src/plat_win.cpp $(HDRS) | $(B)
	$(CXX32) $(CXXFLAGS_COMMON) -municode -o $@ $(CORE_SRC) src/apkinfo.cpp src/plat_win.cpp $(WINLDFLAGS)

$(B)/testhost.exe: tools/testhost.cpp | $(B)
	$(CXX64) $(CXXFLAGS_COMMON) -municode -o $@ tools/testhost.cpp $(WINLDFLAGS) -lgdi32 -luser32

$(B)/testhost32.exe: tools/testhost.cpp | $(B)
	$(CXX32) $(CXXFLAGS_COMMON) -municode -o $@ tools/testhost.cpp $(WINLDFLAGS) -lgdi32 -luser32

# native Linux build of the CLI for quick testing / fuzzing
native: | $(B)
	g++ $(CXXFLAGS_COMMON) -g -o $(B)/apkinfo-native $(CORE_SRC) src/apkinfo.cpp src/plat_posix.cpp

asan: | $(B)
	g++ $(CXXFLAGS_COMMON) -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -o $(B)/apkinfo-asan $(CORE_SRC) src/apkinfo.cpp src/plat_posix.cpp

dist: all
	rm -rf $(B)/dist && mkdir -p $(B)/dist
	cp $(B)/apklister.wlx $(B)/apklister.wlx64 pluginst.inf README.md LICENSE $(B)/dist/
	cd $(B)/dist && rm -f ../apklister-0.1.0.zip && zip -9 -q ../apklister-0.1.0.zip *

clean:
	rm -rf $(B)

.PHONY: all native asan dist clean
