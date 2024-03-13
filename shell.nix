with import <nixpkgs> { };

let python38WithCoolPackages =
  # Use CPython, as:
  #  * PyPy does not seem to support >3.6;
  #  * `pythonPackages` in nixpkgs might not all target PyPy.
  python38.withPackages(ps: with ps; [
    pygraphviz
    z3
  ]);
in
stdenv.mkDerivation rec {
  name = "operation-mango";

  buildInputs = [
    python38Packages.virtualenvwrapper
    python38WithCoolPackages

    nasm
    nmap
    libxml2
    libxslt
    libffi
    readline
    libtool
    glib
    gcc
    graphviz
    debootstrap
    pixman
    openssl
    jdk8
  ];

  shellHook = ''
    source $(command -v virtualenvwrapper.sh)
    if [ -d "$HOME/.virtualenvs/venv3.8" ]; then
      workon venv3.8
    else
      mkvirtualenv venv3.8 -p $(which python3.8)
    fi

    SOURCE_DATE_EPOCH=$(date +%s)

    #
    # Insure that some dependencies are installed
    #
    pip list > pip_list.out

    grep unicorn pip_list.out 2>&1 >/dev/null || UNICORN_QEMU_FLAGS="--python=$(which python2)" pip install unicorn

    for local_dependency in "ailment" "archinfo" "claripy" "cle" "pyelftools" "pyvex" "angr"; do
      grep $local_dependency pip_list.out || pip install -e "../$local_dependency"
    done
  '';
}
