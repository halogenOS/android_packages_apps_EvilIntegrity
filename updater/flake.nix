{
  description = "Android Overlay Generators - Generate overlays for Play Integrity";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        pythonPackages = pkgs.python311Packages;

        # Python dependencies
        pythonDeps = with pythonPackages; [
          requests
        ];

        certified-props-overlay-generator = pkgs.stdenv.mkDerivation rec {
          pname = "certified-props-overlay-generator";
          version = "1.0.0";

          src = ./.;

          buildInputs = [ pythonPackages.python ] ++ pythonDeps;
          nativeBuildInputs = [ pkgs.makeWrapper ];

          installPhase = ''
            mkdir -p $out/bin
            cp certified_props_overlay_generator.py $out/bin/certified-props-overlay-generator
            chmod +x $out/bin/certified-props-overlay-generator

            # Wrap the script with required Python packages
            wrapProgram $out/bin/certified-props-overlay-generator \
              --prefix PYTHONPATH : ${pythonPackages.makePythonPath pythonDeps} \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.coreutils ]}
          '';

          meta = with pkgs.lib; {
            description = "Generates Android fingerprint overlay and pif.json for Play Integrity";
            longDescription = ''
              Automatically fetches latest Pixel Beta fingerprints from Google.
              Generates:
              - pif.json for Play Integrity Fix module
              - Android overlay for certified build properties

              Based on osm0sis' autopif2.sh logic.
            '';
            homepage = "https://github.com/your-org/android-overlay-generators";
            platforms = platforms.all;
          };
        };

        keybox-overlay-generator = pkgs.stdenv.mkDerivation rec {
          pname = "keybox-overlay-generator";
          version = "1.0.0";

          src = ./.;

          buildInputs = [ pythonPackages.python ];
          nativeBuildInputs = [ pkgs.makeWrapper ];

          installPhase = ''
            mkdir -p $out/bin
            cp keybox_overlay_generator.py $out/bin/keybox-overlay-generator
            chmod +x $out/bin/keybox-overlay-generator

            # Wrap the script
            wrapProgram $out/bin/keybox-overlay-generator \
              --prefix PYTHONPATH : ${pythonPackages.makePythonPath []} \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.coreutils ]}
          '';

          meta = with pkgs.lib; {
            description = "Converts keybox.xml files into Android overlay format";
            longDescription = ''
              Processes Android TEE keybox files for hardware attestation.

              WARNING: Keybox files contain private keys and should never
              be shared publicly as they will be revoked by Google.
            '';
            homepage = "https://github.com/your-org/android-overlay-generators";
            platforms = platforms.all;
          };
        };

        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [
            python311
          ] ++ pythonDeps ++ (with pythonPackages; [
            # Development dependencies
            black
            flake8
            mypy
            pytest
            ipython
            types-requests
          ]);

          shellHook = ''
            echo "Android Overlay Generators Development Environment"
            echo "================================================"
            echo ""
            echo "Available scripts:"
            echo "  certified_props_overlay_generator.py - Generate fingerprint overlay"
            echo "  keybox_overlay_generator.py         - Convert keybox.xml to overlay"
            echo ""
            echo "Examples:"
            echo "  # Generate fingerprint overlay"
            echo "  python certified_props_overlay_generator.py"
            echo ""
            echo "  # Use Developer Preview"
            echo "  python certified_props_overlay_generator.py --preview"
            echo ""
            echo "  # Convert keybox.xml"
            echo "  python keybox_overlay_generator.py keybox.xml"
            echo ""
            echo "  # Show keybox format"
            echo "  python keybox_overlay_generator.py --format"
            echo ""
            echo "Development tools:"
            echo "  black *.py       - Format code"
            echo "  flake8 *.py      - Lint code"
            echo "  mypy *.py        - Type check"
            echo ""
          '';
        };

      in
      {
        packages = {
          default = certified-props-overlay-generator;
          certified-props = certified-props-overlay-generator;
          keybox = keybox-overlay-generator;
        };

        apps = {
          default = {
            type = "app";
            program = "${certified-props-overlay-generator}/bin/certified-props-overlay-generator";
          };
          certified-props = {
            type = "app";
            program = "${certified-props-overlay-generator}/bin/certified-props-overlay-generator";
          };
          keybox = {
            type = "app";
            program = "${keybox-overlay-generator}/bin/keybox-overlay-generator";
          };
        };

        devShells.default = devShell;
      });
}
