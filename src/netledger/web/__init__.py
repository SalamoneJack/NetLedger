"""Web console: server-rendered HTML and SVG with a small vanilla-JS layer, no external assets."""

from netledger.web.pages import (
    build_rows,
    overall,
    render_changes,
    render_dashboard,
    render_device,
    render_not_found,
    render_search,
    render_topology,
    render_wall,
    tm_head,
    trend_charts,
    version_rows,
)
from netledger.web.ui import intel_card, render_config, render_diff

__all__ = [
    "build_rows",
    "intel_card",
    "overall",
    "render_changes",
    "render_config",
    "render_dashboard",
    "render_device",
    "render_diff",
    "render_not_found",
    "render_search",
    "render_topology",
    "render_wall",
    "tm_head",
    "trend_charts",
    "version_rows",
]
