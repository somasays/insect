"""Tests for progress_utils.py."""

import io
import time

from insect.utils.progress_utils import (
    ProgressBar,
    format_eta,
    format_time,
    get_scan_progress_formatter,
)


def test_format_time():
    """Test the format_time function."""
    # Test negative time
    assert format_time(-1) == "0s"

    # Test seconds only
    assert format_time(30) == "30s"

    # Test minutes and seconds
    assert format_time(90) == "1m 30s"

    # Test hours, minutes, and seconds
    assert format_time(3661) == "1h 1m 1s"


def test_format_eta():
    """Test the format_eta function."""
    # Test when current progress is 0
    assert format_eta(0, 100, 10) == "ETA: calculating..."

    # Test with a reasonable rate
    assert "ETA:" in format_eta(10, 100, 10)  # Should estimate 90 seconds

    # Test with extreme cases
    assert format_eta(10, 10, 10) == "ETA: 0s"  # Already finished
    assert format_eta(10, 100, 0) == "ETA: calculating..."  # Avoid division by zero


def test_progress_formatter():
    """Test the get_scan_progress_formatter function."""
    formatter = get_scan_progress_formatter()

    # Test basic formatting
    result = formatter(10, 100, 5)
    assert "10/100" in result
    assert "files/s" in result
    assert "ETA:" in result
    assert "Elapsed:" in result

    # Test with prefix
    formatter_with_prefix = get_scan_progress_formatter(prefix="Scanning:")
    result = formatter_with_prefix(10, 100, 5)
    assert "Scanning:" in result


def test_progress_bar_basic():
    """Test basic ProgressBar functionality."""
    # Create a mock stdout
    mock_stdout = io.StringIO()

    # Create a progress bar with the mock stdout
    bar = ProgressBar(
        total=10, dynamic=False, file=mock_stdout
    )  # non-dynamic for testing

    # Start the bar
    bar.start()

    # Update a few times
    for _i in range(1, 11):
        bar.update()

    # Finish the bar
    bar.finish()

    # Check the output
    output = mock_stdout.getvalue()

    # Should contain progress indicators
    assert "|" in output
    assert "100.0%" in output


def test_progress_bar_with_suffix_function():
    """Test ProgressBar with custom suffix function."""
    # Create a mock stdout
    mock_stdout = io.StringIO()

    # Create a suffix function
    def custom_suffix(current, total, elapsed):
        return f"Custom: {current}/{total}"

    # Create a progress bar with the suffix function
    bar = ProgressBar(total=5, dynamic=False, file=mock_stdout)
    bar.set_suffix_function(custom_suffix)

    # Start and update
    bar.start()
    bar.update(3)  # Update to a specific value
    bar.finish()

    # Check the output
    output = mock_stdout.getvalue()

    # Should contain the custom suffix
    assert "Custom: 5/5" in output  # 5/5 because finish() sets to total


def test_progress_bar_dynamic():
    """Test dynamic progress bar updating."""
    # Create a progress bar in dynamic mode
    bar = ProgressBar(total=10, dynamic=True, update_interval=0.1)

    # Start the bar
    bar.start()

    # Let it update itself for a bit
    time.sleep(0.3)

    # Update the progress
    bar.update(5)

    # Let it update itself again
    time.sleep(0.3)

    # Finish the bar - this is what we're really testing:
    # that the dynamic mode can be properly stopped
    bar.finish()

    # If we get here without hanging, the test passes
