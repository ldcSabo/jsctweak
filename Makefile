TARGET := iphone:clang:15.8:15.0
ARCHS := arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = jsctweak

jsctweak_FILES = Tweak_readbit.m
jsctweak_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 com.apple.WebKit.WebContent 2>/dev/null || true"
