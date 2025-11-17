{
  withGUI ? true,
  stdenv,
  lib,
  fetchFromGitHub,

  git,
  cmake,
  openssl,
  pcre,
  util-linux,
  libselinux,
  libsepol,
  pkg-config,
  gdk-pixbuf,
  libnotify,
  libICE,
  libSM,
  libX11,
  libxkbfile,
  libXi,
  libXtst,
  libXrandr,
  libXinerama,
  xkeyboardconfig,
  xinput,
  avahi-compat,
  libsForQt5,
}:

stdenv.mkDerivation rec {
  pname = "synergy";
  version = "1.20.0";

  src = fetchFromGitHub {
    owner = "symless";
    repo = "synergy";
    rev = "v${version}";
    fetchSubmodules = true;
    leaveDotGit = true;
    deepClone = true;
    preFetch = ''
      # can't clone using ssh
      # https://github.com/jg-rp/python-jsonpath/pull/122
      export GIT_CONFIG_COUNT=1
      export GIT_CONFIG_KEY_0=url.https://github.com/.insteadOf
      export GIT_CONFIG_VALUE_0=git@github.com:
    '';
    #hash = "sha256-b0E5iT/Xzx5xqkkqfU0KJfDPJMI4US8LAn+UgwIafKc=";
    #hash = "sha256-kzW/CnJ2+bThxuntPItNVCJGGCkzDcrDsPP9dYcQ0bg=";
    hash = "sha256-VjfV5ZhYJKAhZZBK9gkybFeNkU4z4USOz3uGw4+W1QI=";
    #hash = "";
  };

  patches = [
    # Without this OpenSSL from nixpkgs is not detected
    #./darwin-non-static-openssl.patch
  ];

  postPatch = ''
    #substituteInPlace src/gui/src/SslCertificate.cpp \
    #  --replace-fail 'kUnixOpenSslCommand[] = "openssl";' 'kUnixOpenSslCommand[] = "${openssl}/bin/openssl";'
  ''
  + lib.optionalString stdenv.hostPlatform.isLinux ''
    #substituteInPlace src/lib/synergy/unix/AppUtilUnix.cpp \
    #  --replace-fail "/usr/share/X11/xkb/rules/evdev.xml" "${xkeyboardconfig}/share/X11/xkb/rules/evdev.xml"
  '';

  nativeBuildInputs = [
    git
    cmake
    pkg-config
  ]
  ++ lib.optional withGUI libsForQt5.wrapQtAppsHook;

  buildInputs = [
    libsForQt5.qttools # Used for translations even when not building the GUI
    openssl
    pcre
  ]
  ++ lib.optionals stdenv.hostPlatform.isLinux [
    util-linux
    libselinux
    libsepol
    libICE
    libSM
    libX11
    libXi
    libXtst
    libXrandr
    libXinerama
    libxkbfile
    xinput
    avahi-compat
    gdk-pixbuf
    libnotify
  ];

  # Silences many warnings
  env.NIX_CFLAGS_COMPILE = lib.optionalString stdenv.hostPlatform.isDarwin "-Wno-inconsistent-missing-override";

  cmakeFlags = [
    #"-DVERSION_FILE=version-file=build/VERSION"
  ] ++
    lib.optional (!withGUI) "-DSYNERGY_BUILD_LEGACY_GUI=OFF"
    # NSFilenamesPboardType is deprecated in 10.14+
    ++ lib.optional stdenv.hostPlatform.isDarwin "-DCMAKE_OSX_DEPLOYMENT_TARGET=${
      if stdenv.hostPlatform.isAarch64 then "10.13" else stdenv.hostPlatform.darwinSdkVersion
    }";

  #doCheck = true;

  checkPhase = ''
    runHook preCheck
  ''
  + lib.optionalString stdenv.hostPlatform.isDarwin ''
    # filter out tests failing with sandboxing on darwin
    export GTEST_FILTER=-ServerConfigTests.serverconfig_will_deem_equal_configs_with_same_cell_names:NetworkAddress.hostname_valid_parsing
  ''
  + ''
    bin/unittests
    runHook postCheck
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin
    cp bin/{synergyc,synergys,synergyd,syntool} $out/bin/
  ''
  + lib.optionalString withGUI ''
    cp bin/synergy $out/bin/
  ''
  + lib.optionalString stdenv.hostPlatform.isLinux ''
    mkdir -p $out/share/{applications,icons/hicolor/scalable/apps}
    cp ../res/synergy.svg $out/share/icons/hicolor/scalable/apps/
    substitute ../res/synergy.desktop $out/share/applications/synergy.desktop \
      --replace "/usr/bin" "$out/bin"
  ''
  + lib.optionalString (stdenv.hostPlatform.isDarwin && withGUI) ''
    mkdir -p $out/Applications
    cp -r bundle/Synergy.app $out/Applications
    ln -s $out/bin $out/Applications/Synergy.app/Contents/MacOS
  ''
  + ''
    runHook postInstall
  '';

  dontWrapQtApps = lib.optional (!withGUI) true;

  meta = {
    description = "Share one mouse and keyboard between multiple computers";
    homepage = "https://symless.com/synergy";
    changelog = "https://github.com/symless/synergy-core/blob/${version}/ChangeLog";
    mainProgram = lib.optionalString (!withGUI) "synergyc";
    license = lib.licenses.gpl2Only;
    maintainers = with lib.maintainers; [ talyz ];
    platforms = lib.platforms.unix;
  };
}
