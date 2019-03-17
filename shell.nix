with import <nixpkgs> {}; {
  goEnv = stdenv.mkDerivation {
    name = "go";
    buildInputs = [ go go2nix dep2nix gist ];
    shellHook = ''
      export GOPATH=$HOME/projects/go
      export PATH=$PATH:$GOPATH/bin
      export PS1="\n\[\033[1;32m\][go-shell:\w]$\[\033[0m\] "
    '';
  };
}
