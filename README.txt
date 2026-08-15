NETR4P.R4X
==========

NETR4P.R4X ist die Netzwerk-R4P-Diagnose.

Projektstruktur seit 0.51.21:
- `build.zig` baut die Diagnose als eigenes SDK-Projekt.
- `build.zig.zon` bindet `r4os_sdk` als Paket.
- `module.R4MF` beschreibt Artefakt, Zielpfad, R4L-Imports und Contract.

Build:

    cd Code\System\Diagnostics\NetR4pDiag
    ..\..\..\DevTools\Zig\zig.exe build

Ergebnis:

    Code\System\Diagnostics\NetR4pDiag\zig-out\NETR4P.R4X

Contract:
- Build-Profil: `Zig/R4XStart`
- R4XStart-Entry: `netr4p_main`
- App-Klasse: `console`
- R4L-Imports: `R4SYS`, `R4NET`
- Zielpfad im Image: `C:\R4OS\SOFTWARE\TERMINAL\DIAG\NETR4P.R4X`
