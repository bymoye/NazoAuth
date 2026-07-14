import asyncio
import time
import types
import unittest
from pathlib import Path
from unittest import mock


def load_module():
    patch = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "patches"
        / "oidf-v5.2.0-terminal-info.patch"
    )
    added_function = []
    collecting = False
    for line in patch.read_text(encoding="utf-8").splitlines():
        if line == "+async def read_authoritative_terminal_info(":
            collecting = True
        if collecting and not line.startswith("+"):
            break
        if collecting:
            added_function.append(line[1:])

    namespace = {"asyncio": asyncio, "time": time}
    source = "\n".join(added_function) + "\n"
    exec(compile(source, str(patch), "exec"), namespace)
    return types.SimpleNamespace(
        read_authoritative_terminal_info=namespace["read_authoritative_terminal_info"]
    )


class OidfRunnerConsistencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_stale_waiting_is_reread_until_finished(self):
        module = load_module()
        reader = mock.AsyncMock(
            side_effect=[
                {"status": "WAITING", "result": "PASSED"},
                {"status": "FINISHED", "result": "PASSED"},
            ]
        )

        info = await module.read_authoritative_terminal_info(
            reader,
            "module-id",
            timeout_seconds=1,
            poll_interval_seconds=0,
        )

        self.assertEqual(info, {"status": "FINISHED", "result": "PASSED"})
        self.assertEqual(reader.await_count, 2)

    async def test_persistent_waiting_times_out_fail_closed(self):
        module = load_module()
        reader = mock.AsyncMock(return_value={"status": "WAITING", "result": "PASSED"})

        with self.assertRaisesRegex(TimeoutError, "last status: 'WAITING'"):
            await module.read_authoritative_terminal_info(
                reader,
                "module-id",
                timeout_seconds=0.01,
                poll_interval_seconds=0,
            )

    async def test_finished_failed_result_is_not_changed(self):
        module = load_module()
        failed = {"status": "FINISHED", "result": "FAILED"}
        reader = mock.AsyncMock(return_value=failed)

        info = await module.read_authoritative_terminal_info(reader, "module-id")

        self.assertIs(info, failed)
        self.assertEqual(info["result"], "FAILED")

    async def test_failed_status_fails_closed(self):
        module = load_module()
        reader = mock.AsyncMock(return_value={"status": "FAILED", "result": "PASSED"})

        with self.assertRaisesRegex(RuntimeError, "module-id failed"):
            await module.read_authoritative_terminal_info(reader, "module-id")

    async def test_interrupted_always_fails_closed(self):
        module = load_module()
        for result in ("PASSED", None):
            with self.subTest(result=result):
                reader = mock.AsyncMock(
                    return_value={"status": "INTERRUPTED", "result": result}
                )
                with self.assertRaisesRegex(RuntimeError, "was interrupted"):
                    await module.read_authoritative_terminal_info(reader, "module-id")

    async def test_hung_info_read_is_cancelled_at_deadline(self):
        module = load_module()
        cancelled = asyncio.Event()

        async def reader(_module_id):
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                cancelled.set()
                raise

        with self.assertRaisesRegex(TimeoutError, "did not expose terminal info"):
            await module.read_authoritative_terminal_info(
                reader,
                "module-id",
                timeout_seconds=0.01,
                poll_interval_seconds=0,
            )
        self.assertTrue(cancelled.is_set())

    async def test_api_error_propagates_fail_closed(self):
        module = load_module()
        reader = mock.AsyncMock(side_effect=ConnectionError("suite unavailable"))

        with self.assertRaisesRegex(ConnectionError, "suite unavailable"):
            await module.read_authoritative_terminal_info(reader, "module-id")


if __name__ == "__main__":
    unittest.main()
