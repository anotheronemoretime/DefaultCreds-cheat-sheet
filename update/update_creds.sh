#!/bin/bash

CSV_FILE="../DefaultCreds-Cheat-Sheet.csv"
head -n 1 "$CSV_FILE" > temp_header.csv

python3 extract_nuclei.py > temp_nuclei.csv
python3 extract_cirt.py > temp_cirt.csv

cat temp_nuclei.csv temp_cirt.csv "$CSV_FILE" | sed 's/<blank>//g' | sort -u > temp_combined.csv
cat temp_header.csv temp_combined.csv > "$CSV_FILE"
rm temp_header.csv temp_nuclei.csv temp_cirt.csv temp_combined.csv
