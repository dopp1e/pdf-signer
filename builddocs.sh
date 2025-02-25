#!/bin/bash
typst compile ./report/main.typ
cp ./report/main.pdf ./docs/report.pdf

doxygen Doxyfile