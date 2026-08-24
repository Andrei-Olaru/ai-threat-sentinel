"""Structured JSON logging with structlog.

Dev mode: colorful, human-readable console output.
Production: single-line JSON for machine parsing (ELK/Loki/Datadog).
"""

from __future__ import annotations

import logging
import sys

import structlog


def setup_logging(log_level: str = "INFO", json_format: bool = False) -> None:
    """Configure structured logging for the application.

    Args:
        log_level: Minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        json_format: If True, output JSON (production). If False, pretty console (dev).
    """
    # Processors shared between structlog and stdlib formatter
    shared_processors: list[structlog.types.Processor] = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.format_exc_info,
    ]

    if json_format:
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    # Configure structlog's own pipeline
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure stdlib formatter (for third-party lib logs too)
    # remove_processors_meta MUST only be in the formatter, not in configure()
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level.upper())

    # Suppress noisy third-party loggers
    for noisy in ("uvicorn.access", "httpcore", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance.

    Usage:
        logger = get_logger(__name__)
        logger.info("event_happened", user_id=123, action="login")
    """
    return structlog.get_logger(name)
