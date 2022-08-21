set -Eeuo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

g++ nlelf.cc -Wall -Wextra -Werror -Wconversion -Wshadow --std=c++20 -Os -o "${SCRIPT_DIR}/nlelf"
