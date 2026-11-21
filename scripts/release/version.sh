#!/bin/sh
# EasyRMM's versions (ADR-0052; docs/architecture/edge-manifest.md):
#
#   version.sh release [<commit>]                  the highest release tag reachable from the commit
#   version.sh edge <run> <attempt> [<commit>]     the version of an edge build of the commit
#   version.sh newer <a> <b>                       exits 0 when version a ranks above b, 1 when not
#
# The commit is HEAD unless given. Releases are the tags easyrmm-vX.Y.Z and
# easyrmm-vX.Y.Z-rc.N (no leading zeros, N from 1); other tags are ignored,
# and a full release ranks above its release candidates. With R the highest
# release, an edge build is R.edge.<run>.<attempt> when R is a release
# candidate, else R with its patch raised, -edge.<run>.<attempt>:
#
#   easyrmm-v1.0.0-rc.4   ->  v1.0.0-rc.4.edge.412.1
#   easyrmm-v1.0.0        ->  v1.0.1-edge.415.1
#
# newer compares by semantic versioning's precedence (versions with the v).
# Errors exit 2.
set -eu

die() {
  echo "version: $*" >&2
  exit 2
}

number_re='(0|[1-9][0-9]*)'
release_re="^easyrmm-v$number_re\\.$number_re\\.$number_re(-rc\\.[1-9][0-9]*)?\$"

commit_of() {
  git rev-parse --verify --quiet "$1^{commit}" || die "$1 is not a commit here"
}

release() { # commit
  commit=$(commit_of "$1")
  tags=$(git tag --merged "$commit" --list 'easyrmm-v*' | grep -E "$release_re" || true)
  [ -n "$tags" ] ||
    die "no release tag (easyrmm-vX.Y.Z or easyrmm-vX.Y.Z-rc.N) is reachable from $commit; are the tags fetched?"
  # Sort by X, Y, Z, then a release candidate (0, N) below the release (1, 0).
  printf '%s\n' "$tags" |
    sed -E -e 's/^easyrmm-v([0-9]+)\.([0-9]+)\.([0-9]+)-rc\.([0-9]+)$/\1 \2 \3 0 \4 &/' \
      -e 's/^easyrmm-v([0-9]+)\.([0-9]+)\.([0-9]+)$/\1 \2 \3 1 0 &/' |
    LC_ALL=C sort -k1,1n -k2,2n -k3,3n -k4,4n -k5,5n | tail -n 1 | cut -d' ' -f6
}

edge() { # run attempt commit
  for n in "$1" "$2"; do
    printf '%s' "$n" | grep -Eqx '[1-9][0-9]*' || die "run and attempt must be numbers from 1, got \"$1\" and \"$2\""
  done
  tag=$(release "$3")
  r=${tag#easyrmm-}
  case $r in
    *-rc.*) printf '%s.edge.%s.%s\n' "$r" "$1" "$2" ;;
    *)
      core=${r#v}
      printf '%s-edge.%s.%s\n' "v${core%.*}.$((${core##*.} + 1))" "$1" "$2"
      ;;
  esac
}

newer() { # a b
  for v in "$1" "$2"; do
    printf '%s' "$v" | grep -Eqx "v$number_re\\.$number_re\\.$number_re(-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?" ||
      die "\"$v\" is not a version like v1.2.3 or v1.2.3-rc.1"
  done
  LC_ALL=C awk -v a="${1#v}" -v b="${2#v}" '
    # Digits only: the longer is larger, else byte order (no float rounding).
    function cmpnum(x, y) {
      if (length(x) != length(y)) return length(x) < length(y) ? -1 : 1
      return (x "") < (y "") ? -1 : ((x "") > (y "") ? 1 : 0)
    }
    # A pre-release identifier: numeric ones by value, below alphanumeric ones, which compare in ASCII order.
    function cmpid(x, y,   xn, yn) {
      xn = x ~ /^[0-9]+$/
      yn = y ~ /^[0-9]+$/
      if (xn && yn) return cmpnum(x, y)
      if (xn) return -1
      if (yn) return 1
      return (x "") < (y "") ? -1 : ((x "") > (y "") ? 1 : 0)
    }
    function cmpver(x, y,   i, xc, yc, xp, yp, X, Y, nx, ny, c) {
      i = index(x, "-"); if (i) { xc = substr(x, 1, i - 1); xp = substr(x, i + 1) } else { xc = x; xp = "" }
      i = index(y, "-"); if (i) { yc = substr(y, 1, i - 1); yp = substr(y, i + 1) } else { yc = y; yp = "" }
      split(xc, X, "."); split(yc, Y, ".")
      for (i = 1; i <= 3; i++) if ((c = cmpnum(X[i], Y[i])) != 0) return c
      # A version without a pre-release ranks above the same version with one.
      if (xp == "" || yp == "") return (xp == "") - (yp == "")
      nx = split(xp, X, "."); ny = split(yp, Y, ".")
      for (i = 1; i <= nx && i <= ny; i++) if ((c = cmpid(X[i], Y[i])) != 0) return c
      return nx < ny ? -1 : (nx > ny ? 1 : 0)
    }
    BEGIN { exit cmpver(a, b) > 0 ? 0 : 1 }
  '
}

case ${1:-} in
  release)
    [ $# -le 2 ] || die "usage: version.sh release [<commit>]"
    release "${2:-HEAD}"
    ;;
  edge)
    [ $# -ge 3 ] && [ $# -le 4 ] || die "usage: version.sh edge <run> <attempt> [<commit>]"
    edge "$2" "$3" "${4:-HEAD}"
    ;;
  newer)
    [ $# -eq 3 ] || die "usage: version.sh newer <a> <b>"
    newer "$2" "$3"
    ;;
  *) die "usage: version.sh release [<commit>] | edge <run> <attempt> [<commit>] | newer <a> <b>" ;;
esac
