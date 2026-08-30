#!/bin/sh
set -eu

project_root=/home/joker/AAA_NUS_SEM2/cv_agent
raw_root="$project_root/data/raw"
git_bin=/usr/bin/git

mkdir -p "$raw_root"

fetch_commit() {
  name=$1
  url=$2
  commit=$3
  destination="$raw_root/$name"

  if [ -e "$destination" ] || [ -L "$destination" ]; then
    printf 'DESTINATION_EXISTS=%s\n' "$destination"
    return 20
  fi
  mkdir "$destination"
  "$git_bin" -c init.templateDir= -c init.defaultBranch=main -C "$destination" init
  "$git_bin" -C "$destination" remote add origin "$url"
  "$git_bin" -c protocol.version=2 -C "$destination" fetch --depth=1 origin "$commit"
  "$git_bin" -C "$destination" checkout --detach FETCH_HEAD

  actual=$("$git_bin" -C "$destination" rev-parse HEAD)
  if [ "$actual" != "$commit" ]; then
    printf 'COMMIT_MISMATCH=%s:%s\n' "$name" "$actual"
    return 21
  fi
  if [ -n "$("$git_bin" -C "$destination" status --porcelain)" ]; then
    printf 'DIRTY_CHECKOUT=%s\n' "$name"
    return 22
  fi
  printf 'FETCHED=%s:%s\n' "$name" "$actual"
}

fetch_commit VulnGym https://github.com/Tencent/VulnGym.git cd69f7e163e08485ab5496115ae03439cda6e27e
fetch_commit BenchmarkJava https://github.com/OWASP-Benchmark/BenchmarkJava.git 2734ae486356765ea4e45393a28e20bcb5047f8c
