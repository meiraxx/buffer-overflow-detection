#!/bin/bash
set -e
for file in public_basic_tests/*[^t].json;
do 
	echo ${file}
	python tool.py ${file}
done

for file in public_advanced_tests/*[^t].json;
do 
	echo ${file}
	python tool.py ${file}
done

