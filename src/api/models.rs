//! `GET /v1/models` — static list of Codex models.

use axum::Json;
use serde::Serialize;

use crate::config;

#[derive(Serialize)]
pub struct ModelsResponse {
    pub object: &'static str,
    pub data: Vec<Model>,
}

#[derive(Serialize)]
pub struct Model {
    pub id: String,
    pub object: &'static str,
    pub created: u64,
    pub owned_by: &'static str,
}

pub async fn list() -> Json<ModelsResponse> {
    let data = config::DEFAULT_MODELS
        .iter()
        .map(|m| Model {
            id: m.to_string(),
            object: "model",
            created: 0,
            owned_by: "openai",
        })
        .collect();
    Json(ModelsResponse {
        object: "list",
        data,
    })
}
