kill $(ps aux | grep "aesdsocket -d" | grep -v "grep" | awk '{print $2}')