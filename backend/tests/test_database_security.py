import stat

from ransom_monitor.database import Database


def test_database_and_wal_files_are_private(tmp_path):
    database = Database(tmp_path / "runtime" / "monitor.sqlite3")
    database.initialize()
    with database.connection() as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS permission_test(id INTEGER)")
        connection.execute("INSERT INTO permission_test(id) VALUES (1)")

    assert stat.S_IMODE(database.path.stat().st_mode) == 0o600
    for suffix in ("-wal", "-shm"):
        sidecar = database.path.with_name(database.path.name + suffix)
        if sidecar.exists():
            assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600
