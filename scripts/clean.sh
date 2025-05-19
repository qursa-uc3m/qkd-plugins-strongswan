#!/bin/bash

echo "Cleaning workspace..."

# Try make distclean first if Makefile exists
if [ -f Makefile ]; then
    echo "Running 'make distclean'..."
    make distclean
fi

# Remove object files, libraries and binaries
echo "Removing object files and libraries..."
find . -name "*.o" -delete
find . -name "*.lo" -delete
find . -name "*.la" -delete
find . -name ".libs" -type d -exec rm -rf {} + 2>/dev/null || true
find . -name ".deps" -type d -exec rm -rf {} + 2>/dev/null || true

# Remove autotools generated files
echo "Removing autotools generated files..."
rm -rf aclocal.m4 autom4te.cache/ compile config.* configure depcomp install-sh libtool ltmain.sh
rm -rf ar-lib missing

# Remove all Makefiles and Makefile.in
echo "Removing Makefiles..."
find . -name "Makefile" -delete
find . -name "Makefile.in" -delete

# Remove m4 directory if it only contains libtool files
if [ -d m4 ]; then
    # Check if m4 only contains libtool files
    if [ "$(find m4 -type f -not -name "libtool.m4" -not -name "lt*.m4" | wc -l)" -eq 0 ]; then
        echo "Removing m4 directory..."
        rm -rf m4
    else
        echo "m4 directory contains custom files, not removing"
    fi
fi

# Remove stamp files
echo "Removing stamp files..."
rm -f stamp-h1

# Remove config files
echo "Removing config files..."
rm -f config.h config.h.in config.log config.status

echo "Workspace cleaned successfully!"