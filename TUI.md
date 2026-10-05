<p align="center"><strong>English</strong> | <a href="TUI.zh-CN.md">简体中文</a> | <a href="TUI.ja.md">日本語</a></p>

# Terminal layout and appearance

> These changes are unreleased and describe development builds after v1.6.0.

All five tabs use the available terminal width, with shared section headings and
consistent gaps between adjacent panes. Scrolling tables reserve two cells at the
right for the gap and scrollbar. Host's Interfaces table sizes its columns to the
contents and lets the interface-name column use the remaining width.
Activity's application and Capture headings align below the rate summary.
Graph's process list fits names by terminal-cell width and uses every available
row below its column headings.

## Responsive Host views

Sockets and Interfaces use tables on wide terminals. Below 120 columns, they
switch to wrapped records so addresses, process names, rate digits, and counters
remain readable. Records are also used when unusually long values cannot fit a
wide table. Short socket views also use records to keep every state and endpoint
reachable. No fields are dropped from the compact records.

Use `j` / `k`, arrow keys, Page Up / Page Down, `g` / `G`, or the mouse wheel to
scroll. The footer shows a scroll hint when content extends beyond the viewport.
Host's `v` / Shift+`v` shortcuts still select Sockets, Interfaces, and DNS.

Text truncation measures terminal cells and preserves combining characters and
emoji sequences. Details uses the terminal's full width for its connection
strip, headings, information panes, and aligned RX/TX charts.

Details shows the full dashboard only when every information card and the
traffic plots fit. Otherwise it shows Connection, Network, Process, Application,
Health, and Traffic sections with a shared selector. Press `v` for the next page
or section and Shift+`v` to go back; click a section name to open its first page.
Very short terminals split long sections into numbered pages. Details has no
information scrollbar. `j` / `k`, the up/down arrows, Page Up/Down (or Ctrl+B/F),
and the mouse wheel keep navigating connections. Changing connections preserves
the selected section and starts at its first page. The top connection strip
remains visible when there is room. Traffic retains its paired RX/TX plots where
they fit and uses paged statistics on smaller terminals. Resizing preserves the
selected section, so reducing the terminal restores that view.

Activity keeps TX/RX summary labels and units in fixed columns, with right-aligned
numbers. Changing rates or switching units no longer shifts the readouts.
On wide, tall terminals, the application table keeps its selection and drill-down
and gains two visual summaries below it: application traffic share and interface
traffic share over the last 60 seconds. Press `d` to switch both between TX and
RX. Interface bars compare each interface with the combined interface counters;
these can count the same traffic on multiple interfaces. Live interface rates
use fixed columns, while the bars follow the steadier 60-second totals. Capture
coverage also has TX/RX bars. Smaller terminals and detail views prioritize the
table or selected record; full interface inventory remains available in Host.

## Traffic charts

Graph shows all panels together when the full dashboard fits. Smaller terminals
use Traffic, Health, and Distribution sections, selected with `v` / Shift+`v`
or by clicking their names.
Traffic uses the selected capture interface’s counters and names it in the heading.
The `any` capture interface sums all interface counters, which can count traffic
on more than one interface. Missing counters never fall back to another interface.

Graph and Details plot sampled rates directly, preserving short bursts even
when several samples share a terminal column. The filled curves interpolate
between samples and scroll continuously. Time labels show `-60s`, `-30s`, and
`Now` where space permits. Overview and lifecycle mini waves retain their smoothing.

RX and TX each use an automatic, labeled linear scale in bytes per second
(KiB/MiB/GiB use powers of 1024; compact axes use Ki/Mi/Gi). Compare the numeric readings when comparing directions,
since the two axes can have different bounds. There are no scale, log, or lock
controls. Bounds include the sampled peak, rise to rounded values, and wait five
seconds before gradually shrinking after older peaks leave the history.

Observed idle rates show `0 B/s`; unavailable values retain a placeholder.
Top Processes labels its combined RX+TX rate as a smoothed 10-second average.
Details rates use the same smoothed connection average, identified in the heading
and statistics labels; its `2s avg` averages those displayed samples.

Headers show the current sampled rate, the window peak, and a time-weighted
`2s avg` where space permits. Startup averages use only observed intervals and
appear after two samples. Small traffic can appear near the baseline while a
large burst remains in the 60-second window; the numeric readings remain visible.

The full Details dashboard anchors its paired RX/TX plots above the footer.
The Traffic panel uses about one third of the content height, bounded to 7–18
rows including its heading and statistics, and shrinks to leave every information
card visible. The separate Traffic section uses the available height.
Totals stay on the same row under the current/peak readings,
with the average alongside when it fits. Before history is available or after a
connection closes, the plot shows a status message instead of a moving single point.

In Activity, cycle `s` to `2s Avg TX/RX` to sort by short-term averages. The rate
column then reads `2s Avg/s` and shows the same averaged values used for sorting.
This reduces sensitivity to individual bursts while other sort modes retain their
existing meaning.

Visible scrolling graphs in Overview, Graph, and Details redraw about 20 times
per second, using continuous elapsed time between the existing 500 ms samples.
The scroll position carries across sample arrivals to prevent timing jitter from
jumping the history forward.
Activity share/coverage bars, Host DNS latency bars, and Graph health, protocol,
and TCP-state bars ease toward new values over 250 ms. Numeric readings and
status colors update immediately. Transitions follow each metric's identity
through sorting; new, resized, or newly visible bars show their value immediately.
Settled bars, views without scrolling graphs, and Help use the lower redraw
cadence. Terminal cell resolution still limits the smallest visible movement.

Overview's small activity waves and the connection lifecycle
sparklines retain their compact presentation. In Graph's Health section, scroll
TCP states with the same keys and wheel when they do not all fit.

## Optional Help shadow

Add this to the optional configuration file documented in [Usage](USAGE.md):

```toml
[ui]
popup_shadow = true
```

The default is `false`. The shadow dims the cells beside Help without replacing
underlying text. It is static and adds no animation timer. `NO_COLOR` or
`--no-color` disables the shadow even when the setting is enabled.

## Start with process grouping

Add this to the optional configuration file described in the [usage guide](USAGE.md):

```toml
[view]
group_by_process = true
```

Overview starts with collapsed process groups. The default is `false` (flat).
`a` toggles grouping for the session, `Space` expands a group, and `r` restores
the configured grouping preference. This setting does not affect headless output.
