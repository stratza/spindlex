"""Targeted coverage tests for logging handlers and logger."""

import logging
import os
from unittest.mock import MagicMock, patch

from spindlex.logging.handlers import PerformanceHandler, SecurityHandler
from spindlex.logging.logger import SSHLogger, configure_logging


class TestSecurityHandlerConsole:
    def test_console_handler_created_when_no_filename(self):
        h = SecurityHandler(filename=None)
        assert hasattr(h, "console_handler")

    def test_emit_to_console(self):
        h = SecurityHandler(filename=None)
        h.console_handler = MagicMock()
        record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
        h.emit(record)
        h.console_handler.emit.assert_called_once_with(record)

    def test_close_console_handler(self):
        h = SecurityHandler(filename=None)
        h.console_handler = MagicMock()
        h.close()
        h.console_handler.close.assert_called_once()

    def test_emit_error_calls_handle_error(self):
        h = SecurityHandler(filename=None)
        h.console_handler = MagicMock()
        h.console_handler.emit.side_effect = Exception("boom")
        record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
        with patch.object(h, "handleError") as mock_handle:
            h.emit(record)
            mock_handle.assert_called_once()


class TestPerformanceHandlerConsole:
    def test_console_handler_created_no_filename_no_json(self):
        h = PerformanceHandler(filename=None, json_format=False)
        assert hasattr(h, "console_handler")

    def test_emit_to_console(self):
        h = PerformanceHandler(filename=None, json_format=True)
        h.console_handler = MagicMock()
        record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
        h.emit(record)
        h.console_handler.emit.assert_called_once_with(record)

    def test_close_console_handler(self):
        h = PerformanceHandler(filename=None, json_format=True)
        h.console_handler = MagicMock()
        h.close()
        h.console_handler.close.assert_called_once()

    def test_emit_error_calls_handle_error(self):
        h = PerformanceHandler(filename=None, json_format=True)
        h.console_handler = MagicMock()
        h.console_handler.emit.side_effect = Exception("boom")
        record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
        with patch.object(h, "handleError") as mock_handle:
            h.emit(record)
            mock_handle.assert_called_once()


class TestSSHLoggerMethods:
    def test_debug(self):
        logger = SSHLogger("test_debug")
        with patch.object(logger.logger, "debug") as mock_debug:
            logger.debug("msg %s", "arg")
            mock_debug.assert_called_once_with("msg %s", "arg")

    def test_warning(self):
        logger = SSHLogger("test_warning")
        with patch.object(logger.logger, "warning") as mock_warn:
            logger.warning("warn")
            mock_warn.assert_called_once_with("warn")

    def test_critical(self):
        logger = SSHLogger("test_critical")
        with patch.object(logger.logger, "critical") as mock_crit:
            logger.critical("crit")
            mock_crit.assert_called_once_with("crit")

    def test_exception(self):
        logger = SSHLogger("test_exception")
        with patch.object(logger.logger, "exception") as mock_exc:
            logger.exception("exc")
            mock_exc.assert_called_once_with("exc")

    def test_security_event(self):
        logger = SSHLogger("test_sec")
        logger.security_event(
            "auth_success", "User logged in", client_ip="1.2.3.4", username="bob"
        )
        assert logger._security_logger is not None

    def test_security_event_second_call_reuses_logger(self):
        logger = SSHLogger("test_sec2")
        logger.security_event("x", "first")
        first = logger._security_logger
        logger.security_event("y", "second")
        assert logger._security_logger is first

    def test_performance_metric(self):
        logger = SSHLogger("test_perf")
        logger.performance_metric("connect", 0.123)
        assert logger._performance_logger is not None


class TestConfigureLogging:
    def test_json_format(self, tmp_path):
        configure_logging(format_type="json", output_file=None)

    def test_debug_format(self, tmp_path):
        configure_logging(format_type="debug", output_file=None)

    def test_with_output_file(self, tmp_path):
        log_file = str(tmp_path / "logs" / "app.log")
        configure_logging(output_file=log_file)
        assert os.path.exists(log_file)

    def test_security_and_performance_loggers_configured(self):
        configure_logging(output_file=None)

    def test_string_level(self):
        configure_logging(level="DEBUG")
