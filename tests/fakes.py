"""In-memory stand-ins for psycopg connections/cursors used by the unit tests."""


class FakeCursor:
    def __init__(self, fetchone_queue=None, fetchall_queue=None, rowcount=1) -> None:
        self.fetchone_queue = list(fetchone_queue or [])
        self.fetchall_queue = list(fetchall_queue or [])
        self.rowcount = rowcount
        self.executed: list[tuple[str, tuple]] = []

    def execute(self, sql: str, params=()) -> None:
        self.executed.append((sql, tuple(params) if params is not None else ()))

    def executemany(self, sql: str, params_seq) -> None:
        for params in params_seq:
            self.execute(sql, params)

    def fetchone(self):
        return self.fetchone_queue.pop(0) if self.fetchone_queue else None

    def fetchall(self):
        return self.fetchall_queue.pop(0) if self.fetchall_queue else []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeConnection:
    def __init__(self, cursor: FakeCursor) -> None:
        self._cursor = cursor
        self.committed = False
        self.rolled_back = False

    def cursor(self) -> FakeCursor:
        return self._cursor

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False
