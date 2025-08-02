{ lib
, fetchFromGitHub
, buildGoModule
, installShellFiles
}:

buildGoModule rec {
  pname = "s3-proxy";
  version = "4.18.1";

  src = fetchFromGitHub {
    owner = "oxyno-zeta";
    repo = "s3-proxy";
    rev = "v${version}";
    hash = "sha256-j+Pg+K6hxFHmyvG1swcncMYx0dysJq705A7TLzeJNBU=";
  };

  vendorHash = "sha256-xR65pmIZE3cTKkEw7xeNBBUI/rYfWIZBIebRBOAzzJU=";

  ldflags = [
    "-X github.com/oxyno-zeta/s3-proxy/pkg/s3-proxy/version.Version=${version}"
    "-s"
    "-w"
  ];

  nativeBuildInputs = [ installShellFiles ];

  postInstall = ''
    installShellCompletion --cmd s3-proxy \
      --bash <($out/bin/s3-proxy completion bash) \
      --fish <($out/bin/s3-proxy completion fish) \
      --zsh <($out/bin/s3-proxy completion zsh)
  '';

  meta = with lib; {
    homepage = "https://oxyno-zeta.github.io/s3-proxy/";
    description = "S3 Reverse Proxy with GET, PUT and DELETE methods and authentication";
    license = licenses.asl20;
    maintainers = with maintainers; [ herbetom ];
  };
}
