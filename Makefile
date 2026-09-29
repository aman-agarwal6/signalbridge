PYTHON ?= .venv/bin/python
ifeq ($(OS),Windows_NT)
PYTHON := .venv/Scripts/python.exe
endif
.PHONY: doctor setup up down test test-apps test-bettail verify-m1 verify-core demo demo-core evidence
doctor setup up down test test-apps test-bettail verify-m1 verify-core demo demo-core evidence:
	$(PYTHON) scripts/sb.py $@
