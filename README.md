# GhidraWorker

Eine Verwaltungsoberfläche für Reverse-Engineering-Projekte auf Basis von
[Ghidra](https://github.com/NationalSecurityAgency/ghidra).

EXE (oder DLL, ELF, …) im Datei-Explorer auswählen bzw. ins Fenster ziehen. GhidraWorker
lässt Ghidra die Datei im Hintergrund analysieren und dekompilieren und legt ein Projekt an,
in dem du die Datei Funktion für Funktion nachbaust. Die Projekte bleiben erhalten, du kannst
also jederzeit weitermachen.

## Funktionen

- **Projekt-Dashboard**: alle Binärdateien mit Status, Analysefortschritt und Rebuild-Fortschritt.
- **Analyse auf Knopfdruck**: Ghidra läuft headless (Import, Auto-Analyse, paralleles Dekompilieren),
  mit Fortschrittsbalken, Abbrechen-Knopf und Live-Log.
- **Funktions-Browser**: Suche, Filter und Sortierung. Pro Funktion gibt es den C-Code des Decompilers
  und den Assembler-Code, beide mit Syntax-Hervorhebung und anklickbaren Aufrufen. Dazu Aufrufer und
  aufgerufene Funktionen, API-Aufrufe und verwendete Strings.
- **Arbeitsstand pro Funktion**: Status (*Offen / In Arbeit / Fertig / Ignoriert*), eigene Namen und
  Notizen. Thunks und von Ghidra erkannte Bibliotheksfunktionen (FID) werden automatisch ignoriert.
- **Strings, Imports/Exports, globale Daten und rekonstruierte Typen** als durchsuchbare Tabellen.
- **Rebuild-Gerüst** (siehe unten): ein CMake-C-Projekt mit einer Datei pro Funktion, vorbefüllt mit
  dem Decompiler-Code.
- **Mit Ghidra verzahnt**: Das Ghidra-Projekt lässt sich direkt in der Ghidra-GUI öffnen. *Export
  aktualisieren* übernimmt Änderungen, die du dort gemacht hast. *Umbenennungen übertragen* schreibt
  die in GhidraWorker vergebenen Namen ins Ghidra-Projekt.
- **Downloads**: das Rebuild-Projekt und der komplette Analyse-Export als ZIP.
- Hell/Dunkel-Modus. Die Schrift (Geist) ist lokal eingebunden, die App läuft also komplett offline.

## Voraussetzungen

| | |
|---|---|
| Python | 3.10 oder neuer |
| Java | **JDK** 21+ (nicht nur JRE), z. B. [Eclipse Temurin](https://adoptium.net/) |
| Ghidra | wird bei Bedarf automatisch installiert (aktuelles Release von GitHub) |

## Schnellstart

**Windows:** `start.bat` doppelklicken.
**Linux/macOS:** `./start.sh`

Beim ersten Start legt das Skript eine virtuelle Python-Umgebung an und installiert die
Abhängigkeiten. Danach öffnet sich der Browser unter <http://localhost:8765>.

Ist Ghidra noch nicht installiert, gehst du auf **Einstellungen → Ghidra automatisch installieren**.
Alternativ trägst du dort den Pfad einer vorhandenen Ghidra-Installation ein (oder setzt
`GHIDRA_INSTALL_DIR`).

Ohne Startskript geht es so:

```sh
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m ghidraworker setup-ghidra      # optional: Ghidra-Release installieren
.venv/bin/python -m ghidraworker setup-ghidra --source-only   # optional: Ghidra-Quellcode (GitHub-Repo) klonen
.venv/bin/python -m ghidraworker                   # Oberfläche starten (--port, --host, --no-browser)
.venv/bin/python -m ghidraworker status            # Ghidra/Java-Konfiguration prüfen
```

## Arbeitsablauf

1. **Datei öffnen**: Die Analyse startet automatisch (abschaltbar in den Einstellungen).
2. **Überblick verschaffen**: Einstiegspunkte, Imports und Strings zeigen, was das Programm tut.
3. **Funktionen verstehen**: Im Funktions-Browser vergibst du sprechende Namen und schreibst Notizen.
   Die Namen erscheinen sofort im gesamten Code.
4. **Nachbauen**: Den Code in `rebuild/src/functions/*.c` bereinigen und die Funktion auf **Fertig**
   setzen. Danach *Gerüst neu erzeugen* und bauen:

   ```sh
   cmake -S rebuild -B rebuild/build
   cmake --build rebuild/build
   ```

   Der Linker meldet dann genau die Funktionen, die als Nächstes portiert werden müssen.
5. Für tiefere Analysen öffnest du das Projekt mit **In Ghidra öffnen** in der Ghidra-GUI. Danach Ghidra
   schließen und **Export aktualisieren**.

## Das Rebuild-Gerüst

```
rebuild/
  PLAN.md                  Übersicht, Fortschritt, Import-Bibliotheken, gute Startpunkte
  CMakeLists.txt           Build-Definition (einmalig erzeugt, danach deine Datei)
  cmake/gw_sources.cmake   nur die Funktionen mit Status "Fertig" (wird generiert)
  cmake/gw_libraries.cmake Import-Bibliotheken der Original-Datei (kernel32, user32, …)
  include/gw_ghidra.h      Ghidra-Basistypen (undefined4, ulonglong, …) und Decompiler-Makros
                           (CONCAT44, SUB84, ZEXT48, CARRY4, …), ohne System-Header
  include/gw_types.h       von Ghidra rekonstruierte Strukturen/Typen
  include/gw_imports.h     Deklarationen der importierten API-Funktionen
  include/gw_globals.h     globale Variablen
  include/gw_functions.h   Prototypen aller nachzubauenden Funktionen
  src/main.c               Einstiegspunkt (einmalig erzeugt)
  src/gw_data.c            globale Daten mit den Original-Initialwerten aus der Binärdatei
  src/functions/*.c        eine Datei pro Funktion: Kopfkommentar (Adresse, Aufrufer, Notizen …)
                           und Decompiler-Code
```

Das Gerüst kompiliert von Anfang an und wächst Funktion für Funktion. Beim Neu-Erzeugen werden
**Dateien, die du geändert hast, nie überschrieben** (Erkennung per Hash-Manifest). Nur
unveränderte, generierte Dateien werden aktualisiert, etwa nach einer Umbenennung.

## Wo liegt was?

Alle Daten liegen in `workspace/` (oder im Pfad aus `GW_WORKSPACE`):

```
workspace/
  settings.json
  projects/<projekt-id>/
    project.json   Metadaten und Job-Status
    state.json     dein Arbeitsstand: Status, Namen, Notizen pro Funktion
    input/         die Original-Datei
    ghidra/        das Ghidra-Projekt (gw.gpr), lässt sich in Ghidra öffnen
    analysis/      Export: program/functions/imports/strings/globals.json, types.h,
                   decompiled/*.c, disassembly/*.asm
    rebuild/       das Rebuild-Gerüst (dein Quellcode)
    logs/          Ghidra-Log der letzten Analyse
```

## Aufbau

- `ghidraworker/ghidra_scripts/`: Java-GhidraScripts, die headless laufen.
  `GhidraWorkerExport.java` exportiert alle Daten und dekompiliert parallel.
  `GhidraWorkerPrepare.java` setzt die Analyse-Optionen.
  `GhidraWorkerApplyRenames.java` schreibt die Namen zurück ins Ghidra-Projekt.
- `ghidraworker/jobs.py`: Job-Queue, die `analyzeHeadless` startet und den Fortschritt aus dem
  Log ausliest.
- `ghidraworker/rebuild.py`: Generator für das Rebuild-Gerüst.
- `ghidraworker/app.py`: FastAPI-Backend (REST-API unter `/api`, Doku unter `/docs`).
- `ghidraworker/static/`: Oberfläche (HTML/CSS/JS ohne Build-Schritt).

Der Server lauscht standardmäßig nur auf `127.0.0.1`. Er ist für den lokalen Einsatz gedacht und
hat keine Benutzerverwaltung.

## Entwicklung

```sh
pip install -r requirements-dev.txt
pytest                                                   # Unit- und API-Tests
GHIDRA_INSTALL_DIR=/pfad/zu/ghidra pytest tests/test_e2e.py   # End-to-End (braucht x86_64-w64-mingw32-gcc)
```

## Grenzen

- Decompiler-Code ist ein **Startpunkt**, kein fertiger Quellcode. Typen, Aufrufkonventionen und
  Zeiger in den globalen Daten müssen meist nachgearbeitet werden.
- .NET-Assemblies werden erkannt, sind aber mit ILSpy/dnSpy besser aufgehoben.
- Gepackte oder verschleierte Programme müssen vorher entpackt werden.
- Reverse Engineering nur für Software, bei der du dazu berechtigt bist.

Die Schriften Geist und Geist Mono stehen unter der SIL Open Font License
(`ghidraworker/static/fonts/OFL-Geist.txt`).
