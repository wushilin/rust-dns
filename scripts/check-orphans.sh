#!/bin/bash
# Gate step (O0c): list rust-dns servers whose parent process is gone
# (parent PID 1: a test or script exited without stopping them). Exit 1 if
# there is any. Test suites start servers with RUST_DNS_EXIT_WITH_STDIN=1
# and a stdin pipe, so a server ends with its test process however that
# ends; anything listed here escaped that.
n=0
for p in $(pgrep -f "rust-dns --config" 2>/dev/null); do
  pp=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d " ")
  if [ "$pp" = "1" ]; then
    n=$((n + 1))
    echo "orphan $p $(ps -o etime=,command= -p "$p" | cut -c1-220)"
  fi
done
echo "orphaned rust-dns processes: $n"
[ "$n" -eq 0 ]
