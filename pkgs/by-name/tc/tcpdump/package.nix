{
  lib,
  stdenv,
  fetchFromGitHub,
  libpcap,
  pkg-config,
  perl,
  cmake,
}:

stdenv.mkDerivation rec {
  pname = "tcpdump";
  version = "4.99.5";

  src = fetchFromGitHub {
    owner = "the-tcpdump-group";
    repo = "tcpdump";
    rev = "tcpdump-${version}";
    hash = "sha256-o6WzyfK07E0eyCBttN/3SuR4JcFCRZEuvhmXMOyG/14=";
  };

  postPatch = ''
    patchShebangs tests
  '';

  nativeBuildInputs = [
    cmake
    pkg-config
  ];

  nativeCheckInputs = [ perl ];

  buildInputs = [ libpcap ];

  configureFlags = lib.optional (stdenv.hostPlatform != stdenv.buildPlatform) "ac_cv_linux_vers=2";

  meta = with lib; {
    description = "Network sniffer";
    homepage = "https://www.tcpdump.org/";
    license = licenses.bsd3;
    maintainers = with maintainers; [ globin ];
    platforms = platforms.unix;
    mainProgram = "tcpdump";
  };
}
