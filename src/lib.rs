mod api;
mod diff;
mod git;
mod issues;
mod issues_web;
mod pack;
mod presentation;
mod schema;
mod store;
mod web;

use crate::presentation::{NegotiatedRepresentation, Representation};
use worker::*;

/// Delta compression keyframe interval. A full keyframe is stored every N
/// versions within a blob group. Worst-case reconstruction applies N-1 deltas.
pub const KEYFRAME_INTERVAL: i64 = 50;

// ---------------------------------------------------------------------------
// Identity from trusted X-Ripgit-Actor-* headers.
// These are only set by the auth worker (via service binding) and must never
// be forwarded from the public internet.
// ---------------------------------------------------------------------------

struct Actor {
    display_name: String,
}

fn actor_from_request(req: &Request) -> Option<Actor> {
    let name = req.headers().get("X-Ripgit-Actor-Name").ok()??;
    Some(Actor { display_name: name })
}

/// Returns a deny Response if the actor cannot write to this repo, else None.
/// Ownership is checked by comparing the actor's display_name to the URL owner.
fn check_write_access(actor: &Option<Actor>, repo_owner: &str) -> Option<Result<Response>> {
    match actor {
        None => Some(unauthorized_401()),
        Some(a) if a.display_name == repo_owner => None,
        Some(_) => Some(Response::error(
            "Forbidden: you don't own this repository",
            403,
        )),
    }
}

/// 401 with WWW-Authenticate so git knows to prompt for / retry with credentials.
fn unauthorized_401() -> Result<Response> {
    let mut resp = Response::error("Unauthorized: sign in to push", 401)?;
    resp.headers_mut()
        .set("WWW-Authenticate", r#"Basic realm="ripgit""#)?;
    Ok(resp)
}

/// Build a 302 redirect using an absolute URL.
///
/// `Response::error("", 302)` + manual Location header is unreliable on some
/// Cloudflare Workers runtimes ("unrecognized JavaScript object"). Using
/// `Response::redirect()` with a proper absolute URL avoids this.
fn make_redirect(base_url: &Url, path: &str) -> Result<Response> {
    let abs = format!("{}{}", base_url.origin().ascii_serialization(), path);
    let url = Url::parse(&abs).map_err(|e| Error::RustError(e.to_string()))?;
    Response::redirect(url)
}

fn negotiate_or_response(
    req: &Request,
    supported: &[Representation],
    default: Representation,
) -> std::result::Result<NegotiatedRepresentation, Result<Response>> {
    presentation::preferred_representation(req, supported, default)
        .map_err(|err| err.into_response())
}

fn finalize_negotiated(
    response: Result<Response>,
    selection: &NegotiatedRepresentation,
) -> Result<Response> {
    response.and_then(|resp| presentation::finalize_response(resp, selection))
}

// ---------------------------------------------------------------------------
// Worker entry point — route to the named Repository DO
// ---------------------------------------------------------------------------

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let url = req.url()?;
    let path = url.path();
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // /:owner/ — user profile page (parts = ["owner", ""] with trailing slash,
    // or parts = ["owner"] without). Handled at the Worker level since there
    // is no per-owner DO; it just shows push instructions.
    let is_owner_page = (parts.len() == 1 && !parts[0].is_empty())
        || (parts.len() == 2 && !parts[0].is_empty() && parts[1].is_empty());
    if is_owner_page {
        let owner = parts[0];
        let actor_name = actor_from_request(&req).map(|a| a.display_name);
        let url = req.url()?;
        let repos = list_repos(&env, owner).await;
        let selection = match negotiate_or_response(
            &req,
            &[Representation::Html, Representation::Markdown],
            Representation::Html,
        ) {
            Ok(selection) => selection,
            Err(resp) => return resp,
        };
        return match selection.representation() {
            Representation::Html => finalize_negotiated(
                web::page_owner_profile(owner, actor_name.as_deref(), &url, &repos),
                &selection,
            ),
            Representation::Markdown => finalize_negotiated(
                web::page_owner_profile_markdown(
                    owner,
                    actor_name.as_deref(),
                    &url,
                    &repos,
                    &selection,
                ),
                &selection,
            ),
            Representation::Json => unreachable!(),
        };
    }

    // /:owner/:repo/* — dispatched to a DO instance named "{owner}/{repo}".
    if parts.len() >= 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        let do_name = format!("{}/{}", parts[0], parts[1]);
        let namespace = env.durable_object("REPOSITORY")?;
        let id = namespace.id_from_name(&do_name)?;
        let stub = id.get_stub()?;
        return stub.fetch_with_request(req).await;
    }

    Response::from_json(&serde_json::json!({
        "name": "ripgit",
        "version": "0.1.0",
        "description": "Git remote backed by Cloudflare Durable Objects"
    }))
}

// ---------------------------------------------------------------------------
// Repository Durable Object
// ---------------------------------------------------------------------------

#[durable_object]
pub struct Repository {
    state: State,
    sql: SqlStorage,
    #[allow(dead_code)]
    env: Env,
}

impl DurableObject for Repository {
    fn new(state: State, env: Env) -> Self {
        let state = state;
        let sql = state.storage().sql();
        schema::init(&sql);
        Self { sql, env, state }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path();
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

        // Minimum: [":owner", ":repo"]
        if parts.len() < 2 {
            return Response::error("Not Found", 404);
        }

        let owner = parts[0];
        let repo_name = parts[1];
        let action = if parts.len() >= 3 { parts[2] } else { "" };

        // Resolve the caller's identity from trusted headers (set by auth worker).
        // None means anonymous — allowed for reads, denied for writes.
        let actor = actor_from_request(&req);
        let actor_name = actor.as_ref().map(|a| a.display_name.as_str());

        match (req.method(), action) {
            // -- Git smart HTTP protocol --
            (Method::Get, "info") if parts.get(3) == Some(&"refs") => {
                let service = url
                    .query_pairs()
                    .find(|(k, _)| k == "service")
                    .map(|(_, v)| v.to_string())
                    .unwrap_or_default();
                match service.as_str() {
                    "git-receive-pack" => {
                        if let Some(resp) = check_write_access(&actor, owner) {
                            return resp;
                        }
                        self.advertise_refs("git-receive-pack")
                    }
                    "git-upload-pack" => self.advertise_refs("git-upload-pack"),
                    _ => Response::error("Unsupported service", 403),
                }
            }
            (Method::Post, "git-receive-pack") => {
                if let Some(resp) = check_write_access(&actor, owner) {
                    return resp;
                }
                let body = req.bytes().await?;
                let resp = git::handle_receive_pack(&self.sql, &body)?;
                // On successful push, register the repo in the REGISTRY KV so
                // the owner profile page can list it. Best-effort: never fail the push.
                if resp.status_code() == 200 {
                    let key = format!("repo:{}/{}", owner, repo_name);
                    if let Ok(kv) = self.env.kv("REGISTRY") {
                        if let Ok(builder) = kv.put(&key, "1") {
                            let _ = builder.execute().await;
                        }
                    }
                }
                Ok(resp)
            }
            (Method::Post, "git-upload-pack") => {
                let body = req.bytes().await?;
                git::handle_upload_pack(&self.sql, &body)
            }

            // -- Delete all data (owner only) --
            (Method::Delete, "") => {
                if let Some(resp) = check_write_access(&actor, owner) {
                    return resp;
                }
                self.state.storage().delete_all().await?;
                Response::ok("deleted")
            }

            // -- JSON API (always JSON) --
            (Method::Get, "refs") => api::handle_refs(&self.sql),
            (Method::Get, "file") => api::handle_file(&self.sql, &url),
            (Method::Get, "search") => api::handle_search(&self.sql, &url),
            (Method::Get, "stats") => api::handle_stats(&self.sql),

            // -- Diff / commit history --
            (Method::Get, "diff") => {
                let sha = parts.get(3).unwrap_or(&"");
                let selection = match negotiate_or_response(
                    &req,
                    &[
                        Representation::Json,
                        Representation::Html,
                        Representation::Markdown,
                    ],
                    Representation::Json,
                ) {
                    Ok(selection) => selection,
                    Err(resp) => return resp,
                };
                match selection.representation() {
                    Representation::Json => {
                        finalize_negotiated(diff::handle_diff(&self.sql, sha, &url), &selection)
                    }
                    Representation::Html => finalize_negotiated(
                        web::page_commit(&self.sql, owner, repo_name, sha, actor_name),
                        &selection,
                    ),
                    Representation::Markdown => finalize_negotiated(
                        web::page_diff_markdown(&self.sql, owner, repo_name, sha, &selection),
                        &selection,
                    ),
                }
            }
            (Method::Get, "compare") => {
                let spec = parts.get(3).unwrap_or(&"");
                diff::handle_compare(&self.sql, spec, &url)
            }

            (Method::Get, "log") => {
                let selection = match negotiate_or_response(
                    &req,
                    &[
                        Representation::Json,
                        Representation::Html,
                        Representation::Markdown,
                    ],
                    Representation::Json,
                ) {
                    Ok(selection) => selection,
                    Err(resp) => return resp,
                };
                match selection.representation() {
                    Representation::Json => {
                        finalize_negotiated(api::handle_log(&self.sql, &url), &selection)
                    }
                    Representation::Html => finalize_negotiated(
                        web::page_log(&self.sql, owner, repo_name, &url, actor_name),
                        &selection,
                    ),
                    Representation::Markdown => finalize_negotiated(
                        web::page_log_markdown(&self.sql, owner, repo_name, &url, &selection),
                        &selection,
                    ),
                }
            }
            (Method::Get, "commit") => {
                let hash = parts.get(3).unwrap_or(&"");
                let selection = match negotiate_or_response(
                    &req,
                    &[
                        Representation::Json,
                        Representation::Html,
                        Representation::Markdown,
                    ],
                    Representation::Json,
                ) {
                    Ok(selection) => selection,
                    Err(resp) => return resp,
                };
                match selection.representation() {
                    Representation::Json => {
                        finalize_negotiated(api::handle_commit(&self.sql, hash), &selection)
                    }
                    Representation::Html => finalize_negotiated(
                        web::page_commit(&self.sql, owner, repo_name, hash, actor_name),
                        &selection,
                    ),
                    Representation::Markdown => finalize_negotiated(
                        web::page_commit_markdown(&self.sql, owner, repo_name, hash, &selection),
                        &selection,
                    ),
                }
            }
            // tree/blob by 40-hex hash → JSON API
            (Method::Get, "tree") if is_hex40(parts.get(3).unwrap_or(&"")) => {
                api::handle_tree(&self.sql, parts.get(3).unwrap_or(&""))
            }
            (Method::Get, "blob") if is_hex40(parts.get(3).unwrap_or(&"")) => {
                api::handle_blob(&self.sql, parts.get(3).unwrap_or(&""))
            }

            // -- Web UI --
            (Method::Get, "") => {
                let selection = match negotiate_or_response(
                    &req,
                    &[Representation::Html, Representation::Markdown],
                    Representation::Html,
                ) {
                    Ok(selection) => selection,
                    Err(resp) => return resp,
                };
                match selection.representation() {
                    Representation::Html => finalize_negotiated(
                        web::page_home(&self.sql, owner, repo_name, &url, actor_name),
                        &selection,
                    ),
                    Representation::Markdown => finalize_negotiated(
                        web::page_home_markdown(
                            &self.sql, owner, repo_name, &url, actor_name, &selection,
                        ),
                        &selection,
                    ),
                    Representation::Json => unreachable!(),
                }
            }
            (Method::Get, "commits") => {
                let selection = match negotiate_or_response(
                    &req,
                    &[Representation::Html, Representation::Markdown],
                    Representation::Html,
                ) {
                    Ok(selection) => selection,
                    Err(resp) => return resp,
                };
                match selection.representation() {
                    Representation::Html => finalize_negotiated(
                        web::page_log(&self.sql, owner, repo_name, &url, actor_name),
                        &selection,
                    ),
                    Representation::Markdown => finalize_negotiated(
                        web::page_log_markdown(&self.sql, owner, repo_name, &url, &selection),
                        &selection,
                    ),
                    Representation::Json => unreachable!(),
                }
            }
            (Method::Get, "tree") => {
                let selection = match negotiate_or_response(
                    &req,
                    &[Representation::Html, Representation::Markdown],
                    Representation::Html,
                ) {
                    Ok(selection) => selection,
                    Err(resp) => return resp,
                };
                let ref_name = &decode_path_segment(parts.get(3).unwrap_or(&"main"));
                let sub_path = if parts.len() > 4 {
                    decode_path_segment(&parts[4..].join("/"))
                } else {
                    String::new()
                };
                match selection.representation() {
                    Representation::Html => finalize_negotiated(
                        web::page_tree(
                            &self.sql, owner, repo_name, ref_name, &sub_path, actor_name,
                        ),
                        &selection,
                    ),
                    Representation::Markdown => finalize_negotiated(
                        web::page_tree_markdown(
                            &self.sql, owner, repo_name, ref_name, &sub_path, &selection,
                        ),
                        &selection,
                    ),
                    Representation::Json => unreachable!(),
                }
            }
            (Method::Get, "blob") => {
                let selection = match negotiate_or_response(
                    &req,
                    &[Representation::Html, Representation::Markdown],
                    Representation::Html,
                ) {
                    Ok(selection) => selection,
                    Err(resp) => return resp,
                };
                let ref_name = &decode_path_segment(parts.get(3).unwrap_or(&"main"));
                let sub_path = if parts.len() > 4 {
                    decode_path_segment(&parts[4..].join("/"))
                } else {
                    String::new()
                };
                match selection.representation() {
                    Representation::Html => finalize_negotiated(
                        web::page_blob(
                            &self.sql, owner, repo_name, ref_name, &sub_path, actor_name,
                        ),
                        &selection,
                    ),
                    Representation::Markdown => finalize_negotiated(
                        web::page_blob_markdown(
                            &self.sql, owner, repo_name, ref_name, &sub_path, &selection,
                        ),
                        &selection,
                    ),
                    Representation::Json => unreachable!(),
                }
            }
            (Method::Get, "search-ui") => {
                let selection = match negotiate_or_response(
                    &req,
                    &[Representation::Html, Representation::Markdown],
                    Representation::Html,
                ) {
                    Ok(selection) => selection,
                    Err(resp) => return resp,
                };
                match selection.representation() {
                    Representation::Html => finalize_negotiated(
                        web::page_search(&self.sql, owner, repo_name, &url, actor_name),
                        &selection,
                    ),
                    Representation::Markdown => finalize_negotiated(
                        web::page_search_markdown(&self.sql, owner, repo_name, &url, &selection),
                        &selection,
                    ),
                    Representation::Json => unreachable!(),
                }
            }
            (Method::Get, "settings") => {
                if let Some(resp) = check_write_access(&actor, owner) {
                    return resp;
                }
                let selection = match negotiate_or_response(
                    &req,
                    &[Representation::Html, Representation::Markdown],
                    Representation::Html,
                ) {
                    Ok(selection) => selection,
                    Err(resp) => return resp,
                };
                match selection.representation() {
                    Representation::Html => finalize_negotiated(
                        web::page_settings(&self.sql, owner, repo_name, actor_name),
                        &selection,
                    ),
                    Representation::Markdown => finalize_negotiated(
                        web::page_settings_markdown(&self.sql, owner, repo_name, &selection),
                        &selection,
                    ),
                    Representation::Json => unreachable!(),
                }
            }
            (Method::Post, "settings") => {
                if let Some(resp) = check_write_access(&actor, owner) {
                    return resp;
                }
                let sub = parts.get(3).copied().unwrap_or("");
                self.handle_settings_action(owner, repo_name, sub, &url, req)
                    .await
            }
            (Method::Get, "raw") => {
                let ref_name = &decode_path_segment(parts.get(3).unwrap_or(&"main"));
                let sub_path = if parts.len() > 4 {
                    decode_path_segment(&parts[4..].join("/"))
                } else {
                    String::new()
                };
                web::serve_raw(&self.sql, ref_name, &sub_path)
            }

            // -- Issues --
            (Method::Get, "issues") => {
                let sub = parts.get(3).copied().unwrap_or("");
                if sub == "new" && actor.is_none() {
                    return unauthorized_401();
                }
                let issue_number = if sub.is_empty() || sub == "new" {
                    None
                } else {
                    match sub.parse::<i64>() {
                        Ok(num) => Some(num),
                        Err(_) => return Response::error("Not Found", 404),
                    }
                };

                let selection = match negotiate_or_response(
                    &req,
                    &[Representation::Html, Representation::Markdown],
                    Representation::Html,
                ) {
                    Ok(selection) => selection,
                    Err(resp) => return resp,
                };

                match selection.representation() {
                    Representation::Html => match (sub, issue_number) {
                        ("", _) => finalize_negotiated(
                            issues_web::page_issues_list(
                                &self.sql, owner, repo_name, &url, actor_name,
                            ),
                            &selection,
                        ),
                        ("new", _) => finalize_negotiated(
                            issues_web::page_new_issue(&self.sql, owner, repo_name, actor_name),
                            &selection,
                        ),
                        (_, Some(num)) => finalize_negotiated(
                            issues_web::page_issue_detail(
                                &self.sql, owner, repo_name, num, actor_name,
                            ),
                            &selection,
                        ),
                        _ => Response::error("Not Found", 404),
                    },
                    Representation::Markdown => match (sub, issue_number) {
                        ("", _) => finalize_negotiated(
                            issues_web::page_issues_list_markdown(
                                &self.sql, owner, repo_name, &url, actor_name, &selection,
                            ),
                            &selection,
                        ),
                        ("new", _) => finalize_negotiated(
                            issues_web::page_new_issue_markdown(
                                &self.sql, owner, repo_name, actor_name, &selection,
                            ),
                            &selection,
                        ),
                        (_, Some(num)) => finalize_negotiated(
                            issues_web::page_issue_detail_markdown(
                                &self.sql, owner, repo_name, num, actor_name, &selection,
                            ),
                            &selection,
                        ),
                        _ => Response::error("Not Found", 404),
                    },
                    Representation::Json => unreachable!(),
                }
            }
            (Method::Post, "issues") => {
                if actor.is_none() {
                    return unauthorized_401();
                }
                let sub3 = parts.get(3).copied().unwrap_or("");
                let sub4 = parts.get(4).copied().unwrap_or("");
                let aname = actor_name.unwrap_or("");
                self.handle_issue_action(owner, repo_name, sub3, sub4, "issues", aname, &url, req)
                    .await
            }

            // -- Pull requests --
            (Method::Get, "pulls") => {
                let sub = parts.get(3).copied().unwrap_or("");
                if sub == "new" && actor.is_none() {
                    return unauthorized_401();
                }
                let pull_number = if sub.is_empty() || sub == "new" {
                    None
                } else {
                    match sub.parse::<i64>() {
                        Ok(num) => Some(num),
                        Err(_) => return Response::error("Not Found", 404),
                    }
                };

                let selection = match negotiate_or_response(
                    &req,
                    &[Representation::Html, Representation::Markdown],
                    Representation::Html,
                ) {
                    Ok(selection) => selection,
                    Err(resp) => return resp,
                };

                match selection.representation() {
                    Representation::Html => match (sub, pull_number) {
                        ("", _) => finalize_negotiated(
                            issues_web::page_pulls_list(
                                &self.sql, owner, repo_name, &url, actor_name,
                            ),
                            &selection,
                        ),
                        ("new", _) => finalize_negotiated(
                            issues_web::page_new_pull(
                                &self.sql, owner, repo_name, &url, actor_name,
                            ),
                            &selection,
                        ),
                        (_, Some(num)) => finalize_negotiated(
                            issues_web::page_issue_detail(
                                &self.sql, owner, repo_name, num, actor_name,
                            ),
                            &selection,
                        ),
                        _ => Response::error("Not Found", 404),
                    },
                    Representation::Markdown => match (sub, pull_number) {
                        ("", _) => finalize_negotiated(
                            issues_web::page_pulls_list_markdown(
                                &self.sql, owner, repo_name, &url, actor_name, &selection,
                            ),
                            &selection,
                        ),
                        ("new", _) => finalize_negotiated(
                            issues_web::page_new_pull_markdown(
                                &self.sql, owner, repo_name, &url, actor_name, &selection,
                            ),
                            &selection,
                        ),
                        (_, Some(num)) => finalize_negotiated(
                            issues_web::page_issue_detail_markdown(
                                &self.sql, owner, repo_name, num, actor_name, &selection,
                            ),
                            &selection,
                        ),
                        _ => Response::error("Not Found", 404),
                    },
                    Representation::Json => unreachable!(),
                }
            }
            (Method::Post, "pulls") => {
                if actor.is_none() {
                    return unauthorized_401();
                }
                let sub3 = parts.get(3).copied().unwrap_or("");
                let sub4 = parts.get(4).copied().unwrap_or("");
                let aname = actor_name.unwrap_or("");
                self.handle_issue_action(owner, repo_name, sub3, sub4, "pulls", aname, &url, req)
                    .await
            }

            // -- Admin endpoints (owner only) --
            (Method::Put, "admin") => {
                if let Some(resp) = check_write_access(&actor, owner) {
                    return resp;
                }
                let sub = parts.get(3).unwrap_or(&"");
                match *sub {
                    "set-ref" => {
                        let name = url
                            .query_pairs()
                            .find(|(k, _)| k == "name")
                            .map(|(_, v)| v.to_string());
                        let hash = url
                            .query_pairs()
                            .find(|(k, _)| k == "hash")
                            .map(|(_, v)| v.to_string());
                        match (name, hash) {
                            (Some(n), Some(h)) => {
                                self.sql.exec(
                                    "INSERT INTO refs (name, commit_hash) VALUES (?, ?)
                                     ON CONFLICT(name) DO UPDATE SET commit_hash = ?",
                                    vec![
                                        SqlStorageValue::from(n.clone()),
                                        SqlStorageValue::from(h.clone()),
                                        SqlStorageValue::from(h.clone()),
                                    ],
                                )?;
                                Response::ok(format!("{} -> {}", n, h))
                            }
                            _ => Response::ok("need ?name=refs/heads/main&hash=abc123"),
                        }
                    }
                    "config" => {
                        let key = url
                            .query_pairs()
                            .find(|(k, _)| k == "key")
                            .map(|(_, v)| v.to_string());
                        let value = url
                            .query_pairs()
                            .find(|(k, _)| k == "value")
                            .map(|(_, v)| v.to_string());
                        match (key, value) {
                            (Some(k), Some(v)) => {
                                store::set_config(&self.sql, &k, &v)?;
                                Response::ok(format!("{} = {}", k, v))
                            }
                            (Some(k), None) => {
                                let v = store::get_config(&self.sql, &k)?;
                                Response::ok(v.unwrap_or_else(|| "(not set)".to_string()))
                            }
                            _ => Response::ok("need ?key=name[&value=val]"),
                        }
                    }
                    "rebuild-fts" => {
                        let default_ref = store::get_config(&self.sql, "default_branch")?
                            .unwrap_or_else(|| "refs/heads/main".to_string());
                        #[derive(serde::Deserialize)]
                        struct RefRow {
                            commit_hash: String,
                        }
                        let rows: Vec<RefRow> = self
                            .sql
                            .exec(
                                "SELECT commit_hash FROM refs WHERE name = ?",
                                vec![SqlStorageValue::from(default_ref)],
                            )?
                            .to_array()?;
                        if let Some(row) = rows.first() {
                            store::rebuild_fts_index(&self.sql, &row.commit_hash)?;
                            Response::ok("fts rebuilt")
                        } else {
                            Response::ok("no default branch ref found")
                        }
                    }
                    "rebuild-graph" => {
                        // Bulk rebuild commit graph using INSERT...SELECT per level.
                        // ~14 SQL calls for any repo size.
                        self.sql.exec("DELETE FROM commit_graph", None)?;

                        // Level 0: direct first-parent
                        self.sql.exec(
                            "INSERT INTO commit_graph (commit_hash, level, ancestor_hash)
                             SELECT cp.commit_hash, 0, cp.parent_hash
                             FROM commit_parents cp WHERE cp.ordinal = 0",
                            None,
                        )?;

                        let mut level: i64 = 1;
                        loop {
                            let prev = level - 1;
                            let result = self.sql.exec(
                                &format!(
                                    "INSERT INTO commit_graph (commit_hash, level, ancestor_hash)
                                     SELECT cg.commit_hash, {}, cg2.ancestor_hash
                                     FROM commit_graph cg
                                     JOIN commit_graph cg2
                                       ON cg2.commit_hash = cg.ancestor_hash AND cg2.level = {}
                                     WHERE cg.level = {}",
                                    level, prev, prev
                                ),
                                None,
                            )?;
                            if result.rows_written() == 0 {
                                break;
                            }
                            level += 1;
                        }

                        Response::ok(format!("commit graph rebuilt ({} levels)", level))
                    }
                    "rebuild-fts-commits" => {
                        // Bulk rebuild fts_commits from all commits
                        self.sql.exec("DELETE FROM fts_commits", None)?;
                        self.sql.exec(
                            "INSERT INTO fts_commits (hash, message, author)
                             SELECT hash, message, author FROM commits",
                            None,
                        )?;
                        #[derive(serde::Deserialize)]
                        struct Count {
                            n: i64,
                        }
                        let rows: Vec<Count> = self
                            .sql
                            .exec("SELECT COUNT(*) AS n FROM fts_commits", None)?
                            .to_array()?;
                        let n = rows.first().map(|r| r.n).unwrap_or(0);
                        Response::ok(format!("fts_commits rebuilt ({} entries)", n))
                    }
                    _ => Response::error("unknown admin action", 404),
                }
            }

            _ => Response::error("Not Found", 404),
        }
    }
}

// ---------------------------------------------------------------------------
// Git protocol helpers
// ---------------------------------------------------------------------------

impl Repository {
    /// Handle POST /:owner/:repo/{issues,pulls}/:sub3/:sub4
    async fn handle_issue_action(
        &self,
        owner: &str,
        repo_name: &str,
        sub3: &str,       // "" | "new" | "<number>"
        sub4: &str,       // "" | "comment" | "close" | "reopen" | "merge"
        kind_url: &str,   // "issues" | "pulls"
        actor_name: &str, // already validated non-empty by caller
        req_url: &Url,    // for building absolute redirect URLs
        mut req: Request,
    ) -> Result<Response> {
        let kind = if kind_url == "pulls" { "pr" } else { "issue" };

        // POST /{issues|pulls}  →  create
        if sub3.is_empty() {
            let body = req.text().await?;
            let form = issues::parse_form(&body);
            let title = form
                .get("title")
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            let body_text = form.get("body").cloned().unwrap_or_default();

            if title.is_empty() {
                return Response::error("title is required", 400);
            }

            if kind == "pr" {
                let source = form.get("source").cloned().unwrap_or_default();
                let target = form.get("target").cloned().unwrap_or_default();
                if source.is_empty() || target.is_empty() {
                    return Response::error("source and target branches are required", 400);
                }
                if source == target {
                    return Response::error("source and target branches must differ", 400);
                }
                let source_ref = format!("refs/heads/{}", source);
                let source_hash = match api::resolve_ref(&self.sql, &source_ref)? {
                    Some(h) => Some(h),
                    None => return Response::error("source branch not found", 404),
                };
                let number = issues::create_issue(
                    &self.sql,
                    kind,
                    &title,
                    &body_text,
                    actor_name,
                    actor_name,
                    Some(&source),
                    Some(&target),
                    source_hash.as_deref(),
                )?;
                return make_redirect(
                    req_url,
                    &format!("/{}/{}/{}/{}", owner, repo_name, kind_url, number),
                );
            } else {
                let number = issues::create_issue(
                    &self.sql, kind, &title, &body_text, actor_name, actor_name, None, None, None,
                )?;
                return make_redirect(
                    req_url,
                    &format!("/{}/{}/{}/{}", owner, repo_name, kind_url, number),
                );
            }
        }

        // POST /{issues|pulls}/:n/...
        let number: i64 = match sub3.parse() {
            Ok(n) => n,
            Err(_) => return Response::error("Not Found", 404),
        };

        match sub4 {
            "comment" => {
                let body = req.text().await?;
                let form = issues::parse_form(&body);
                let comment_body = form.get("body").cloned().unwrap_or_default();
                let issue = issues::get_issue(&self.sql, number)?
                    .ok_or_else(|| Error::RustError("not found".into()))?;
                issues::create_comment(&self.sql, issue.id, &comment_body, actor_name, actor_name)?;
            }
            "close" => {
                issues::set_issue_state(&self.sql, number, "closed", actor_name, owner)?;
            }
            "reopen" => {
                issues::set_issue_state(&self.sql, number, "open", actor_name, owner)?;
            }
            "merge" => {
                // Only repo owner can merge
                if actor_name != owner {
                    return Response::error("Forbidden: only the repo owner can merge", 403);
                }
                let target_branch =
                    issues::get_issue(&self.sql, number)?.and_then(|issue| issue.target_branch);
                match issues::merge_pr(&self.sql, number, actor_name) {
                    Ok(merge_hash) => {
                        if let Some(target_branch) = target_branch {
                            if let Some(default_ref) =
                                store::get_config(&self.sql, "default_branch")?
                            {
                                if default_ref == format!("refs/heads/{}", target_branch) {
                                    let _ = store::rebuild_fts_index(&self.sql, &merge_hash);
                                }
                            }
                        }
                    }
                    Err(e) => return Response::error(&e.to_string(), 409),
                }
            }
            _ => return Response::error("Not Found", 404),
        }

        make_redirect(
            req_url,
            &format!("/{}/{}/{}/{}", owner, repo_name, kind_url, number),
        )
    }

    /// Handle POST /:owner/:repo/settings/:action — all owner-only mutations.
    async fn handle_settings_action(
        &self,
        owner: &str,
        repo_name: &str,
        action: &str,
        req_url: &Url,
        mut req: Request,
    ) -> Result<Response> {
        let settings_path = format!("/{}/{}/settings", owner, repo_name);

        let back = || -> Result<Response> { make_redirect(req_url, &settings_path) };

        match action {
            "rebuild-graph" => {
                self.sql.exec("DELETE FROM commit_graph", None)?;
                self.sql.exec(
                    "INSERT INTO commit_graph (commit_hash, level, ancestor_hash)
                     SELECT cp.commit_hash, 0, cp.parent_hash
                     FROM commit_parents cp WHERE cp.ordinal = 0",
                    None,
                )?;
                let mut level: i64 = 1;
                loop {
                    let prev = level - 1;
                    let result = self.sql.exec(
                        &format!(
                            "INSERT INTO commit_graph (commit_hash, level, ancestor_hash)
                             SELECT cg.commit_hash, {level}, cg2.ancestor_hash
                             FROM commit_graph cg
                             JOIN commit_graph cg2
                               ON cg2.commit_hash = cg.ancestor_hash AND cg2.level = {prev}
                             WHERE cg.level = {prev}",
                            level = level,
                            prev = prev,
                        ),
                        None,
                    )?;
                    if result.rows_written() == 0 {
                        break;
                    }
                    level += 1;
                }
                back()
            }

            "rebuild-fts-commits" => {
                self.sql.exec("DELETE FROM fts_commits", None)?;
                self.sql.exec(
                    "INSERT INTO fts_commits (hash, message, author)
                     SELECT hash, message, author FROM commits",
                    None,
                )?;
                back()
            }

            "rebuild-fts" => {
                let default_ref = store::get_config(&self.sql, "default_branch")?
                    .unwrap_or_else(|| "refs/heads/main".to_string());
                #[derive(serde::Deserialize)]
                struct RefRow {
                    commit_hash: String,
                }
                let rows: Vec<RefRow> = self
                    .sql
                    .exec(
                        "SELECT commit_hash FROM refs WHERE name = ?",
                        vec![SqlStorageValue::from(default_ref)],
                    )?
                    .to_array()?;
                if let Some(row) = rows.first() {
                    store::rebuild_fts_index(&self.sql, &row.commit_hash)?;
                }
                back()
            }

            "default-branch" => {
                let body = req.text().await?;
                let branch = body
                    .split('&')
                    .find_map(|pair| {
                        let mut kv = pair.splitn(2, '=');
                        if kv.next() == Some("branch") {
                            kv.next().map(|v| v.replace('+', " "))
                        } else {
                            None
                        }
                    })
                    .unwrap_or_default();
                let branch = branch.trim();
                if !branch.is_empty() {
                    store::set_config(&self.sql, "default_branch", branch)?;
                }
                back()
            }

            "delete" => {
                let body = req.text().await?;
                let confirm_val = body
                    .split('&')
                    .find_map(|pair| {
                        let mut kv = pair.splitn(2, '=');
                        if kv.next() == Some("confirm") {
                            kv.next().map(|v| {
                                // minimal URL decode for / (%2F) and spaces
                                v.replace('+', " ").replace("%2F", "/").replace("%2f", "/")
                            })
                        } else {
                            None
                        }
                    })
                    .unwrap_or_default();

                let expected = format!("{}/{}", owner, repo_name);
                if confirm_val.trim() == expected {
                    self.state.storage().delete_all().await?;
                    make_redirect(req_url, &format!("/{}/", owner))
                } else {
                    // Wrong confirmation — bounce back to settings
                    back()
                }
            }

            _ => Response::error("Not Found", 404),
        }
    }

    /// Ref advertisement for both receive-pack and upload-pack.
    /// Returns current refs in pkt-line format so git knows what we have.
    fn advertise_refs(&self, service: &str) -> Result<Response> {
        let content_type = format!("application/x-{}-advertisement", service);

        // Collect current refs
        #[derive(serde::Deserialize)]
        struct RefRow {
            name: String,
            commit_hash: String,
        }
        let refs: Vec<RefRow> = self
            .sql
            .exec("SELECT name, commit_hash FROM refs", None)?
            .to_array()?;

        let mut body = Vec::new();

        // Service announcement
        let svc_line = format!("# service={}\n", service);
        pkt_line(&mut body, &svc_line);
        body.extend_from_slice(b"0000"); // flush

        // Build capabilities, including symref for HEAD.
        // upload-pack and receive-pack speak different capability sets.
        let default_branch = store::get_config(&self.sql, "default_branch")?
            .unwrap_or_else(|| "refs/heads/main".to_string());
        let caps = match service {
            "git-upload-pack" => format!(
                "multi_ack_detailed no-done ofs-delta side-band-64k no-progress symref=HEAD:{}",
                default_branch
            ),
            _ => format!(
                "report-status delete-refs ofs-delta side-band-64k quiet symref=HEAD:{}",
                default_branch
            ),
        };

        if refs.is_empty() {
            // Empty repo: advertise zero-id with capabilities
            let line = format!(
                "0000000000000000000000000000000000000000 capabilities^{{}}\0{}\n",
                caps
            );
            pkt_line(&mut body, &line);
        } else {
            // Find the default branch's commit for HEAD
            let head_hash = refs
                .iter()
                .find(|r| r.name == default_branch)
                .map(|r| r.commit_hash.clone());

            let mut first = true;

            // Advertise HEAD first (so git clone checks out the right branch)
            if let Some(ref hh) = head_hash {
                let line = format!("{} HEAD\0{}\n", hh, caps);
                pkt_line(&mut body, &line);
                first = false;
            }

            for r in refs.iter() {
                let line = if first {
                    first = false;
                    format!("{} {}\0{}\n", r.commit_hash, r.name, caps)
                } else {
                    format!("{} {}\n", r.commit_hash, r.name)
                };
                pkt_line(&mut body, &line);
            }
        }
        body.extend_from_slice(b"0000"); // flush

        let mut resp = Response::from_bytes(body)?;
        resp.headers_mut().set("Content-Type", &content_type)?;
        resp.headers_mut().set("Cache-Control", "no-cache")?;
        Ok(resp)
    }
}

// ---------------------------------------------------------------------------
// Pkt-line encoding
// ---------------------------------------------------------------------------

/// Append a pkt-line encoded string to the buffer.
/// Pkt-line format: 4 hex digits for total length (including the 4 digits),
/// followed by the payload.
fn pkt_line(buf: &mut Vec<u8>, data: &str) {
    let len = 4 + data.len();
    buf.extend_from_slice(format!("{:04x}", len).as_bytes());
    buf.extend_from_slice(data.as_bytes());
}

/// Percent-decode a URL path segment (e.g. `my%20file.txt` -> `my file.txt`).
/// Unlike form decoding, `+` is left as-is. Invalid escapes pass through unchanged.
fn decode_path_segment(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Check if a string is a 40-character hex SHA-1 hash.
/// Used to distinguish API calls (by hash) from web UI calls (by ref + path).
fn is_hex40(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// List repos registered in the REGISTRY KV for the given owner.
/// Keys are stored as "repo:{owner}/{repo}".
/// Returns an empty list if the KV binding is unavailable or the list fails.
async fn list_repos(env: &Env, owner: &str) -> Vec<String> {
    let prefix = format!("repo:{}/", owner);
    let kv = match env.kv("REGISTRY") {
        Ok(kv) => kv,
        Err(_) => return vec![],
    };
    match kv.list().prefix(prefix.clone()).execute().await {
        Ok(result) => result
            .keys
            .into_iter()
            .map(|k| k.name[prefix.len()..].to_string())
            .collect(),
        Err(_) => vec![],
    }
}
