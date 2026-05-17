//! Per-tab renderers. Each submodule owns the rendering for one
//! tab (Overview, Details, Interfaces, Graph, Help) and is invoked
//! from the top-level `draw()` dispatcher in `ui::mod`.

pub(super) mod details;
pub(super) mod graph;
pub(super) mod help;
pub(super) mod interfaces;
pub(super) mod overview;
