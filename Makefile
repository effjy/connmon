CC      ?= cc
PKGS    := gtk+-3.0
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
CFLAGS  += $(shell pkg-config --cflags $(PKGS))
LDFLAGS += $(shell pkg-config --libs $(PKGS))

TARGET  := connmon
SRC     := connmon.c

PREFIX     ?= /usr/local
BINDIR     := $(DESTDIR)$(PREFIX)/bin
DATADIR    := $(DESTDIR)$(PREFIX)/share
DESKTOPDIR := $(DATADIR)/applications
ICONDIR    := $(DATADIR)/icons/hicolor/scalable/apps

.PHONY: all clean run install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

install: $(TARGET)
	install -d $(BINDIR) $(DESKTOPDIR) $(ICONDIR)
	install -m 0755 $(TARGET) $(BINDIR)/$(TARGET)
	install -m 0644 connmon.svg $(ICONDIR)/connmon.svg
	install -m 0644 connmon.desktop $(DESKTOPDIR)/connmon.desktop
	-gtk-update-icon-cache -f -t $(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(DESKTOPDIR) 2>/dev/null || true
	@echo "Installed $(TARGET). Look for 'Connection Monitor' in your application menu."

uninstall:
	rm -f $(BINDIR)/$(TARGET)
	rm -f $(ICONDIR)/connmon.svg
	rm -f $(DESKTOPDIR)/connmon.desktop
	-gtk-update-icon-cache -f -t $(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(DESKTOPDIR) 2>/dev/null || true
	@echo "Uninstalled $(TARGET)."

clean:
	rm -f $(TARGET)
