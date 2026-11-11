#!/usr/bin/env bash
# Measures the coverage of src/ by the fuzz corpora, merged across targets.
#
# Usage: fuzz/coverage.sh [--fuzz SECONDS] [--html] [TARGET...]
#
# Replays each target's corpus in fuzz/corpus/<target>, built by `cargo +nightly fuzz run <target>`,
# and prints one report merged across the targets. Defaults to every target; pass a single target
# for its own coverage. --fuzz first fuzzes each target for SECONDS on every core, creating or
# growing its corpus. --html also writes a per-line report to fuzz/coverage/html/index.html.
#
# Requires cargo-fuzz and the nightly llvm-tools-preview component.
set -euo pipefail

cd "$(dirname "$0")/.."

html=false
fuzz_seconds=0
targets=()
while [ $# -gt 0 ]; do
    case $1 in
        --html) html=true ;;
        --fuzz)
            fuzz_seconds=${2:?--fuzz needs a number of seconds}
            shift
            ;;
        -h | --help)
            sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) targets+=("$1") ;;
    esac
    shift
done
if [ ${#targets[@]} -eq 0 ]; then
    while read -r target; do
        targets+=("$target")
    done < <(cargo +nightly fuzz list)
fi

# The profiles must be read by the LLVM tools of the toolchain which wrote them
host=$(rustc +nightly -vV | sed -n 's/^host: //p')
tools=$(rustc +nightly --print sysroot)/lib/rustlib/$host/bin
if [ ! -x "$tools/llvm-cov" ]; then
    echo "llvm-cov not found, install it with: rustup component add --toolchain nightly llvm-tools-preview" >&2
    exit 1
fi

if [ "$fuzz_seconds" -gt 0 ]; then
    jobs=$(getconf _NPROCESSORS_ONLN)
    for target in "${targets[@]}"; do
        echo "Fuzzing $target for $fuzz_seconds seconds with $jobs jobs"
        # A crash or slow input stops the script, leaving the reproducer in fuzz/artifacts/<target>
        cargo +nightly fuzz run "$target" -- \
            -max_total_time="$fuzz_seconds" -fork="$jobs" -timeout=10
    done
fi

measured=()
profiles=()
objects=()
for target in "${targets[@]}"; do
    if [ -z "$(ls -A "fuzz/corpus/$target" 2>/dev/null)" ]; then
        echo "Skipping $target: its corpus is empty. Fuzz it first, e.g. with: fuzz/coverage.sh --fuzz 60 $target" >&2
        continue
    fi
    measured+=("$target")
    cargo +nightly fuzz coverage "$target"
    profiles+=("fuzz/coverage/$target/coverage.profdata")
    # llvm-cov takes the first binary as an argument and the rest as -object options
    binary=target/$host/coverage/$host/release/$target
    if [ ${#objects[@]} -eq 0 ]; then
        objects+=("$binary")
    else
        objects+=(-object "$binary")
    fi
done
if [ ${#profiles[@]} -eq 0 ]; then
    echo "No corpora to measure" >&2
    exit 1
fi

merged=fuzz/coverage/merged.profdata
"$tools/llvm-profdata" merge -sparse "${profiles[@]}" -o "$merged"
echo
echo "Coverage of src/ by: ${measured[*]}"
"$tools/llvm-cov" report "${objects[@]}" -instr-profile="$merged" "$PWD/src"
if $html; then
    "$tools/llvm-cov" show "${objects[@]}" -instr-profile="$merged" "$PWD/src" \
        -format=html -show-line-counts-or-regions -output-dir=fuzz/coverage/html
    echo "Per-line report: fuzz/coverage/html/index.html"
fi
