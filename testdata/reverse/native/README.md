# Native runner fixtures

The source fixture used by opt-in container acceptance is `../native_fixture.c`.
Compile it as a Linux x86-64 ELF on the dedicated lab host; never run the
result directly on the ARTEX host. The default unit suite uses synthetic ELF
headers and mocked Docker subprocesses only.
