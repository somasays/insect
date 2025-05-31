"""
Progress bar utilities for Insect.

This module provides a progress bar implementation for tracking long-running operations.
"""

import sys
import threading
import time
from typing import Callable, Optional


class ProgressBar:
    """A progress bar for tracking long-running operations."""

    def __init__(
        self,
        total: int,
        prefix: str = "",
        suffix: str = "",
        decimals: int = 1,
        length: int = 50,
        fill: str = "█",
        print_end: str = "\r",
        file=sys.stdout,  # type: ignore[assignment]
        update_interval: float = 0.1,
        dynamic: bool = True,
    ) -> None:
        """Initialize the progress bar.

        Args:
            total: Total number of items to process.
            prefix: String to print before the progress bar.
            suffix: String to print after the progress bar.
            decimals: Number of decimal places to display in the percentage.
            length: Character length of the progress bar.
            fill: Character to use for the progress bar fill.
            print_end: Character to use at the end of the line.
            file: File to write the progress bar to.
            update_interval: Seconds between updates when in dynamic mode.
            dynamic: Whether to use a separate thread to update the progress bar.
        """
        self.total = total
        self.prefix = prefix
        self.suffix = suffix
        self.decimals = decimals
        self.length = length
        self.fill = fill
        self.print_end = print_end
        self.file = file
        self.update_interval = update_interval
        self.dynamic = dynamic

        # Internal state
        self._iteration = 0
        self._start_time: Optional[float] = None
        self._lock = threading.RLock()
        self._update_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._current_suffix = suffix
        self._custom_suffix_fn: Optional[Callable[[int, int, float], str]] = None
        self._is_finished = False

    def set_suffix_function(self, fn: Callable[[int, int, float], str]) -> None:
        """Set a function to dynamically generate the suffix.

        Args:
            fn: Function that takes (iteration, total, elapsed_time) and returns a string.
        """
        self._custom_suffix_fn = fn

    def start(self) -> None:
        """Start the progress bar and initialize the timer."""
        self._start_time = time.time()
        self._iteration = 0
        self._is_finished = False
        self._stop_event.clear()

        # Print initial progress bar
        self._print_progress()

        # Start update thread if in dynamic mode
        if self.dynamic:
            self._update_thread = threading.Thread(target=self._update_loop)
            self._update_thread.daemon = True
            self._update_thread.start()

    def update(self, iteration: Optional[int] = None) -> None:
        """Update the progress bar.

        Args:
            iteration: Current iteration (if None, increments by 1).
        """
        with self._lock:
            if iteration is not None:
                self._iteration = iteration
            else:
                self._iteration += 1

            # Don't print if using dynamic updates (handled by thread)
            if not self.dynamic:
                self._print_progress()

    def finish(self) -> None:
        """Finish the progress bar."""
        with self._lock:
            # Set iteration to total for clean display
            self._iteration = self.total
            self._is_finished = True
            self._print_progress()
            print(file=self.file)  # newline after progress bar

        # Stop the update thread
        self._stop_event.set()
        if self._update_thread and self._update_thread.is_alive():
            self._update_thread.join(timeout=1.0)

    def _update_loop(self) -> None:
        """Thread function to update the progress bar continuously."""
        while not self._stop_event.is_set():
            with self._lock:
                if not self._is_finished:
                    self._print_progress()
            time.sleep(self.update_interval)

    def _print_progress(self) -> None:
        """Print the progress bar."""
        elapsed_time = time.time() - self._start_time if self._start_time else 0
        percent = 100 * (self._iteration / float(self.total))
        filled_length = int(self.length * self._iteration // self.total)
        bar = self.fill * filled_length + "-" * (self.length - filled_length)

        # Calculate suffix dynamically if function is provided
        if self._custom_suffix_fn:
            self._current_suffix = self._custom_suffix_fn(
                self._iteration, self.total, elapsed_time
            )

        # Format the progress bar
        progress_str = f"\r{self.prefix} |{bar}| {percent:.{self.decimals}f}% {self._current_suffix}"
        print(f"\r{' ' * (len(progress_str)-1)}", end="\r", file=self.file)
        print(progress_str, end=self.print_end, file=self.file)
        self.file.flush()


def format_time(seconds: float) -> str:
    """Format seconds into a human-readable time string.

    Args:
        seconds: Seconds to format.

    Returns:
        Formatted time string (e.g., "1h 2m 3s").
    """
    if seconds < 0:
        return "0s"

    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)

    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes > 0:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def format_eta(current: int, total: int, elapsed: float) -> str:
    """Calculate and format the estimated time of arrival (ETA).

    Args:
        current: Current progress.
        total: Total items to process.
        elapsed: Time elapsed so far in seconds.

    Returns:
        Formatted ETA string.
    """
    if current <= 0 or elapsed <= 0:
        return "ETA: calculating..."

    items_per_second = current / elapsed
    if items_per_second <= 0:
        return "ETA: calculating..."

    remaining_items = total - current
    eta_seconds = remaining_items / items_per_second

    return f"ETA: {format_time(eta_seconds)}"


def get_scan_progress_formatter(
    prefix: str = "", show_speed: bool = True
) -> Callable[[int, int, float], str]:
    """Get a formatter function for scan progress.

    Args:
        prefix: Prefix for the suffix.
        show_speed: Whether to show processing speed.

    Returns:
        Function that formats progress information.
    """

    def formatter(current: int, total: int, elapsed: float) -> str:
        parts = []

        # Add count
        parts.append(f"{current}/{total}")

        # Add speed if requested
        if show_speed and elapsed > 0:
            speed = current / elapsed
            parts.append(f"{speed:.1f} files/s")

        # Add ETA
        parts.append(format_eta(current, total, elapsed))

        # Add elapsed time
        parts.append(f"Elapsed: {format_time(elapsed)}")

        suffix = " | ".join(parts)
        if prefix:
            suffix = f"{prefix} {suffix}"

        return suffix

    return formatter
