from datetime import datetime, timezone
from cybersentinel.ingestion.normalizer import parse_sysmon

def test_parse_sysmon_extracts_properties():
    record = {
        "EventID": "1",
        "UtcTime": "2026-09-14 20:00:00.000",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c echo hello",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ParentCommandLine": "explorer.exe",
        "Hashes": "SHA1=1234567890ABCDEF",
        "CurrentDirectory": "C:\\Users\\admin\\",
        "OriginalFileName": "Cmd.Exe",
        "IntegrityLevel": "High"
    }

    event = parse_sysmon(record)

    # Core fields
    assert event.process_name == "C:\\Windows\\System32\\cmd.exe"
    assert event.command_line == "cmd.exe /c echo hello"
    assert event.parent_process == "C:\\Windows\\explorer.exe"

    # Properties
    assert event.properties["parent_command_line"] == "explorer.exe"
    # SysmonCollector parsea "ALGO=valor,ALGO=valor" a {algo: valor} -- lo
    # que ya esperaba cti/enrichment.py (extract_observables hace
    # hashes.values()); el parser hand-rolled anterior devolvia la cadena
    # cruda, que habria roto esa llamada con AttributeError.
    assert event.properties["hashes"] == {"sha1": "1234567890ABCDEF"}
    assert event.properties["current_directory"] == "C:\\Users\\admin\\"
    assert event.properties["original_file_name"] == "Cmd.Exe"
    assert event.properties["integrity_level"] == "High"
