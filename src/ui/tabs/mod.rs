//! Per-view renderers. Each submodule owns one tab or the contextual
//! help overlay and is invoked from the top-level UI dispatcher.

pub(super) mod activity;
pub(super) mod details;
pub(super) mod graph;
pub(super) mod help;
pub(super) mod interfaces;
pub(super) mod overview;
