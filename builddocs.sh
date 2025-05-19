#!/bin/bash
typst compile ./report/main.typ
cp ./report/main.pdf ./docs/report.pdf

doxygen Doxyfile
cd ./docs/latex
make

cd ..
pdfunite \
    ./report.pdf \
    ./latex/refman.pdf \
    ./report-combined.pdf