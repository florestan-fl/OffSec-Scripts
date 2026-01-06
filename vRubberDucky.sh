#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail

# Default delays (milliseconds)
DELAY_CHAR=1
DELAY_LINE=2

# ----------------------------
# Argument parsing
# ----------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        -w|--window-id)
            # Ensure a value is provided and is not another option
            if [[ -n "${2:-}" && "$2" != -* ]]; then
                WINDOW_ID="$2"
                shift 2
            else
                echo "Error: --window-id requires a value" >&2
                exit 1
            fi
            ;;
        -f|--file)
            # Ensure a value is provided and the file exists
            if [[ -n "${2:-}" && "$2" != -* && -f "$2" ]]; then
                FILE="$2"
                shift 2
            else
                echo "Error: --file requires a valid file" >&2
                exit 1
            fi
            ;;
        --delay-character)
            # Delay between characters; must be a non-negative integer
            if [[ -n "${2:-}" && "$2" =~ ^[0-9]+$ ]]; then
                DELAY_CHAR="$2"
                shift 2
            else
                echo "Error: --delay-character requires a non-negative integer" >&2
                exit 1
            fi
            ;;
        --delay-line)
            # Delay between lines; must be a non-negative integer
            if [[ -n "${2:-}" && "$2" =~ ^[0-9]+$ ]]; then
                DELAY_LINE="$2"
                shift 2
            else
                echo "Error: --delay-line requires a non-negative integer" >&2
                exit 1
            fi
            ;;
        -h|--help)
            echo_help
            ;;
        --)
            # Explicit end of options
            shift
            break
            ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
        *)
            # Positional arguments are not expected
            break
            ;;
    esac
done

# ----------------------------
# Mandatory argument validation
# ----------------------------
if [[ -z "${FILE:-}" || -z "${WINDOW_ID:-}" ]]; then
    echo_help
fi

# ----------------------------
# Window activation
# ----------------------------
# Ensure the target window is focused before typing
xdotool windowactivate "$WINDOW_ID"
sleep 0.5

# ----------------------------
# File typing loop
# ----------------------------
# Read file line by line, tracking whether the line ended with a newline
while IFS= read -r line; do
    xdotool type \
        --delay "$DELAY_CHAR" \
        --clearmodifiers \
        --window "$WINDOW_ID" \
        "$line"

    # Send Return because read succeeded due to a newline
    xdotool key \
        --delay "$DELAY_LINE" \
        --clearmodifiers \
        --window "$WINDOW_ID" \
        Return
done < "$FILE"

# Handle final line without trailing newline
if [ -n "$line" ]; then
    xdotool type \
        --delay "$DELAY_CHAR" \
        --clearmodifiers \
        --window "$WINDOW_ID" \
        "$line"
fi
