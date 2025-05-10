#!/bin/bash

# Script to empty the logs directory except for the last (most recent) log file.

LOG_DIR="logs"

# Check if the log directory exists
if [ ! -d "$LOG_DIR" ]; then
    echo "Log directory '$LOG_DIR' not found."
    exit 1
fi

# Change to the log directory to make file operations simpler
cd "$LOG_DIR" || exit 1

# Count the number of files in the directory
# Using find to correctly handle filenames with spaces or special characters
# and to only count regular files (-type f) directly in this directory (-maxdepth 1)
num_files=$(find . -maxdepth 1 -type f -print | wc -l)

if [ "$num_files" -le 1 ]; then
    echo "No old log files to remove (found $num_files file(s))."
    # Change back to the original directory before exiting
    cd - > /dev/null
    exit 0
fi

# List all files, sort by modification time (newest first), then skip the first one (the newest)
# and pass the rest to xargs for deletion.
# `ls -t` sorts by modification time.
# `tail -n +2` skips the first line.
# `xargs -d '\n'` handles filenames with spaces.
files_to_delete=$(ls -t | tail -n +2)

if [ -n "$files_to_delete" ]; then
    echo "Removing the following old log files:"
    # Loop through files to print them before deleting
    echo "$files_to_delete" | while IFS= read -r file_to_delete; do
        echo " - $file_to_delete"
    done
    # Actual deletion
    echo "$files_to_delete" | xargs -d '\n' rm -f
    
    # Count how many were actually passed to xargs (can be tricky if names have newlines)
    # A simpler way is to count lines from the `files_to_delete` variable
    num_deleted=$(echo "$files_to_delete" | wc -l)
    echo "Successfully removed $num_deleted old log file(s)."
else
    echo "No old log files to remove."
fi

# Change back to the original directory
cd - > /dev/null
exit 0
