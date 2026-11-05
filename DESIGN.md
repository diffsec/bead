# bead: design

bead is a memory service for coding agents. It keeps all memory as Markdown files with YAML frontmatter on disk. A local proxy delivers memory to the model, so the agent does not have to ask for it. A nightly job grooms the store. A curation session lets a person reinforce, delete and seal memories.

## Requirements

The design follows three findings from the brief:

1. Retrieval method moves accuracy by about 20 points. The write strategy moves it by 3 to 8 points. The design therefore keeps the raw history and puts effort into retrieval, not into clever writes.
2. Similarity retrieval served superseded values 15 to 40% of the time. A deterministic supersession rule brought that to about 0%. The design therefore gives each fact a typed key and a version, and a rule, not a model, picks the current value.
3. An agent with a full store made 0 memory calls in 114 turns. Cue-triggered injection fired every time. The design therefore puts delivery in the harness path, not in an optional tool.

Other requirements:

- It must work with any harness that lets the user set the API base URL.
- Deletion must remove the content everywhere, including raw history and the index.
- One user for now. Every record carries an owner field so that multi-user support does not need a data migration.

## Components

| Component | Job |
| --- | --- |
| `bead store` | Reads and writes OKF files. It enforces the supersession rule. |
| `bead index` | A SQLite FTS5 index that gives BM25 ranking. It is derived from the files and can be rebuilt at any time. |
| `bead proxy` | An HTTP proxy for the Anthropic Messages API, and later the OpenAI API. It captures turns and injects memory. |
| `bead dream` | The nightly grooming job. |
| `bead curate` | The interactive curation session. It is an admin MCP server plus a launcher. |
| `bead` CLI | Search, show, forget, seal, rebuild the index, and run evals. |

The files are the source of truth. The index, the proxy and the dream job hold no state that the files do not hold.

## Storage layout

```
~/.bead/
  config.yaml
  store/
    raw/2026/11/05/<session-id>.md        # append-only turn log, one file per session
    facts/<scope>/<key>/v1.md             # one file per version of a typed fact
    facts/<scope>/<key>/v2.md
    episodes/2026/11/05/<id>.md           # dream summaries: situation, action, outcome, lesson
  sealed/                                 # age-encrypted facts, never auto-injected
  index.db                                # derived, safe to delete
  audit.log                               # append-only: writes, supersedes, deletes, tombstones
```

The scope is `user`, `project/<name>` or `global`. The proxy derives the project name from the working directory or the git remote that the harness reports.

## Storage format decision

bead uses its own frontmatter schema, not OKF. OKF is Markdown with YAML frontmatter too, so the files have the same shape. The difference is who controls the fields.

The supersession rule, the tombstones and the injection filter depend on `key`, `version`, `trust`, `sensitivity` and `owner`. A change to an outside specification at v0.2 must not be able to break those rules. An OKF export (`bead export --okf`) can come later, after the field mapping is checked against the published specification.

Each version is a separate file, `facts/<key>/v<N>.md`. One file per version keeps every old value readable and gives each version a stable path for `sources` links.

## Fact format

Each fact version is one Markdown file.

```markdown
---
id: project/bead/language@v2
key: project/bead/language
type: project            # user | feedback | project | reference
owner: ben
status: current          # current | superseded | dormant | sealed
version: 2
supersedes: project/bead/language@v1
valid_from: 2026-11-05T09:12:00Z
trust: user_stated       # user_stated | agent_observed | dream_inferred
sensitivity: private     # public | private | secret
sources:
  - raw/2026/11/05/3f2a.md#turn-14
last_injected: 2026-11-05T10:01:00Z
pinned: false
---
The project is written in Go.
```

## Supersession rule

The rule is deterministic and runs on every write:

1. The current version of a key is the file with the highest version number. The `status` field is written for readers, but the rule does not read it.
2. A write takes an exclusive `flock` on the store, writes `v<N+1>.md`, and then marks `v<N>.md` as `superseded`. A crash between the two steps leaves the old file saying `current`, but rule 1 still picks the new file.
3. A write whose body and type match the current version writes nothing. This stops repeated dream runs from making new versions.
4. Retrieval for injection returns only current versions.
5. A history query can return all versions of a key in order.

A model never decides which value is current. A model can only propose a `key` for a fact that has none. The dream job does that, and a key match then triggers the same rule.

Two facts that conflict but have different keys are a key-assignment error. The dream job puts them in the review queue. It does not resolve them by itself.

## Retrieval

Retrieval is BM25 over two corpora:

- Current facts, with a boost for `trust: user_stated` and for the active scope.
- Raw turn chunks, which supply context that no extracted fact holds.

Embeddings are out of scope for the first version. The brief shows that BM25 over raw history with full context is competitive. Add a vector stage only if the eval set shows a gap that BM25 does not close.

## Delivery through the proxy

The harness points its base URL at the proxy, for example `ANTHROPIC_BASE_URL=http://127.0.0.1:7077`. The proxy forwards every request to the real API with the caller's own key. It does not store the key.

For each request the proxy does these steps:

1. Extract cues from the newest user turn: the text, file paths, symbols, tool names and the error text in tool results.
2. Run retrieval with those cues. Keep the results that are over a score threshold, up to a token budget. The default budget is 1,500 tokens.
3. Inject the results into the request.
4. Forward the request. Stream the response back to the harness without change.
5. Tee the request and the response into the raw log for the session.

The proxy injects memory in two places, because of prompt caching:

- The pinned block holds `user` and `feedback` facts and the facts for the active project. It is fixed for the life of a session, so it goes at the end of the system prompt and the cache prefix stays valid.
- The cue block holds the per-turn results. It goes in a text block added to the newest user message. The earlier turns do not change, so the cache for them stays valid.

The proxy marks each injected block with a `<bead-memory>` tag. On capture it strips its own tags, so injected memory never enters the raw log as new evidence.

### Proxy implementation

Start the proxy with `bead proxy`. Then start the harness with `ANTHROPIC_BASE_URL=http://127.0.0.1:7077`. The proxy refuses a listen address that is not a loopback address.

- The session is the `X-Bead-Session` header. If that is absent, the session is Claude Code's `x-claude-code-session-id` header. For a subagent, a hash of `x-claude-code-agent-id` is added. If both are absent, the session is a hash of the system prompt and the first message. A harness resends the full conversation each turn, so this prefix is stable.
- The proxy appends blocks by splicing them into the raw JSON array. Existing blocks keep their exact bytes. Claude Code puts an attribution block first in `system`, and `api.anthropic.com` strips it only when it arrives unchanged in that position ([gateway protocol](https://code.claude.com/docs/en/llm-gateway-protocol#system-prompt-attribution-block)). `cache_control` markers also stay in place.
- The project is the `X-Bead-Project` header. If the header is absent, the project is the base name of the `working directory:` path in the system prompt. Then the `--project` flag applies.
- The proxy keeps a state file for each conversation in `~/.bead/sessions/<session>-<thread>.jsonl`. The thread is a hash of the first message, which separates side requests that share the session header. The file records the pinned block, every recall block with the message it went into, the injected fact and raw IDs, and the last captured message index. The proxy reads it on each request, so a proxy restart or a `bead forget` in another process takes effect at once.
- The harness resends earlier turns without the blocks that the proxy added. The proxy therefore adds every earlier recall block again, at the same message, with the same bytes. Without this, the prompt cache misses from the first injected turn to the end of the conversation. `TestClaudeCodeShape` checks that the earlier messages are byte-identical between turns.
- A fact or raw excerpt is injected once per conversation, because the earlier block stays in the context. A retry of a request sends the same bytes and captures nothing twice.
- The pinned block is built on the first request of a conversation and stored in the state file. A fact written during the conversation does not appear in it until the next conversation.
- `forget` removes matching lines from the state files, so the proxy stops adding a forgotten value. This costs one cache miss at that point.
- `bead proxy --trace FILE`, or `BEAD_TRACE`, appends one JSON line per request: the message roles, the cues, the injected IDs and the rejected candidates with their scores.
- Claude Code ends each request with `role: "system"` messages after the newest user message. The proxy skips them to find the newest user turn. It finds the working directory in the system prompt, in a system message, or in the first user message.
- Cues are the newest user message, plus the text and tool calls of the assistant message before it. Tool results are cut to 1,500 characters. `<system-reminder>` blocks, tool labels and JSON field names such as `"command"` are removed, because they repeat in every turn.
- Fact selection is in `internal/recall`. BM25 finds candidates. The evidence score weights each shared term by its IDF among the stored facts (body and last key segment), scaled so that a term only one fact has weighs 1. A short list of generic development words weighs 0.2. "Evaluation" gives the default gate and the reason for it.
- The proxy labels the person's own text `[user]` in the cues, so recall can weight it above tool output.
- Raw excerpts leave out the current session and its subagents (`<session>-<agent hash>`), and the same text is injected once per conversation.
- Raw excerpts still use the term-coverage check at 0.25, and up to 2 excerpts from other sessions are injected.
- Capture writes the user turn before forwarding and the assistant turn when the response body ends. It skips thinking blocks. The client gets the response bytes unchanged, including server-sent events.
- `POST /v1/messages` is the only path that the proxy changes. Other paths, such as `/v1/messages/count_tokens`, pass through unchanged.
- If the body is not valid JSON or injection fails, the proxy forwards the original body.

### Service and shell setup

`bead setup` is the one command that sets up a machine. It does these steps on macOS:

1. It writes a default `~/.bead/config.yaml` with mode `0600` if none exists. It never changes an existing file. The default uses Ollama with no model, so the dream job reports the missing model until you set one.
2. If the vault does not exist and a person is at the terminal, it offers to create it and asks for the passphrase twice. In a script it prints a hint instead. `--no-vault` skips this step.
3. It writes `~/Library/LaunchAgents/com.bead.proxy.plist`. The agent starts the proxy at login and restarts it if it exits (`RunAtLoad` and `KeepAlive`). The log is `~/.bead/proxy.log`.
4. It writes `com.bead.dream.plist` for the nightly run. `--no-dream` skips this step.
5. It loads both agents with `launchctl bootout` and `launchctl bootstrap`. `--no-load` skips this step.
6. It writes `~/.bead/shell.sh`, and adds a marked block to `~/.zshrc` or `~/.bashrc` that sources it. `--no-rc` skips the rc change. A second run changes nothing.

`shell.sh` defines a `claude` shell function. The function checks `GET /bead/health` on the proxy with a timeout of 1 second. If the proxy answers, the function runs Claude Code with `ANTHROPIC_BASE_URL` and `CLAUDE_CODE_GATEWAY_HINT_HEADERS=1`. If the proxy does not answer, the function prints a warning and runs Claude Code directly, so a stopped proxy never blocks work. The function sets no credential, so the subscription login stays active.

The agents store the path of the `bead` binary. `bead setup` refuses a binary from `go run` or a temporary directory. Install it first with `go install github.com/diffsec/bead/cmd/bead@latest`.

To remove the setup, delete the marked block from the rc file, and run `launchctl bootout gui/$(id -u)/com.bead.proxy` and `launchctl bootout gui/$(id -u)/com.bead.dream`.

### Claude Team and Enterprise subscriptions

The proxy works with a claude.ai subscription login. When only `ANTHROPIC_BASE_URL` is set, Claude Code keeps the saved claude.ai login as its credential ([LLM gateway](https://code.claude.com/docs/en/llm-gateway)). The proxy forwards `Authorization` and `anthropic-beta` unchanged. The `anthropic-beta` header carries an OAuth capability, and the API returns `401` without it. The proxy stores neither header. `TestSubscriptionAuthHeadersPassThrough` covers this.

Start Claude Code like this:

```sh
ANTHROPIC_BASE_URL=http://127.0.0.1:7077 \
CLAUDE_CODE_GATEWAY_HINT_HEADERS=1 \
claude
```

Do not set `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`, because either one replaces the subscription login. `CLAUDE_CODE_GATEWAY_HINT_HEADERS=1` needs Claude Code v2.1.273 or later, and it makes Claude Code send `x-claude-code-session-id`. Remote Control does not work while the base URL is not `api.anthropic.com`. An administrator can block custom providers with `allowedProviders` in managed settings.

An MCP server gives the agent explicit `recall` and `remember` tools as well. These tools are a supplement. Delivery does not depend on them.

## Capture and writes

The proxy writes raw turns as they happen. That is the only automatic write. Before it writes, it runs a secret scan with gitleaks-style rules. A match is replaced with `[REDACTED:<rule>]` in the file.

Facts come from three places:

- The user says "remember X" in a session. The proxy detects this and writes a `user_stated` fact at once.
- The agent calls the `remember` tool. This writes an `agent_observed` fact.
- The dream job extracts facts from raw history. These are `dream_inferred` facts.

## Nightly dream job

`launchd` on macOS, or `cron` elsewhere, runs `bead dream` once a night. The job works only on raw sessions since the last run.

The model backend is set in `~/.bead/config.yaml`. Three providers are supported: `ollama` (the default), `anthropic`, and `openai` for any OpenAI-compatible endpoint. The file holds the name of the environment variable that contains the API key, never the key itself.

```yaml
owner: ben
dream:
  provider: anthropic        # ollama | anthropic | openai
  model: claude-haiku-5-5
  # base_url and api_key_env have defaults for each provider
```

The job has these phases:

1. Extract. A model reads each new session and proposes typed facts. Each proposal has a key, a value and a pointer to the source turn.
2. Reconcile. The store applies the supersession rule to proposals with a known key. Proposals that conflict with a different key go to the review queue.
3. Consolidate. The job merges duplicate facts and writes one episode summary per session.
4. Decay. A fact that has not been injected for 60 days and is not pinned becomes `dormant`. A dormant fact stays searchable but is not auto-injected.
5. Report. The job writes `store/reports/<date>.md`, which lists every change and every item in the review queue.

The dream job never deletes. It only adds versions, supersedes and demotes, so a person can reverse every change it makes.

### Dream implementation

`bead dream run` does one pass. `--dry-run` calls the model and writes the report, but changes no memory and does not mark sessions as read. `bead dream install` writes `~/Library/LaunchAgents/com.bead.dream.plist` for 03:07 local time, and prints the `launchctl bootstrap` command. It does not load the job by itself. On other systems it prints a crontab line.

`store/dream/state.json` records how many turns of each session the job read. A run sends only the newer turns. A session with a model error is not marked, so the next run tries it again. A `flock` on `store/dream/.lock` stops two runs at the same time.

The model sees the current keys and values for the session's scopes, up to 200, so that it reuses keys. The transcript goes inside `<transcript>` tags, with numbered turns, and the system prompt says that the transcript is data. A call holds up to 24,000 characters of transcript, and one turn is cut to 4,000.

Each proposal goes through these rules in order:

1. Reject an invalid key or type, an empty body, a body over 600 characters, or a body that the credential scan changes.
2. Skip a value that has a tombstone. This covers forgotten values and rejected review items.
3. Queue a value that reads like an instruction to a model (`suspicious`).
4. Queue a value that the model says replaces a fact with a different key (`key-conflict`).
5. Queue a change to a value with trust `user_stated` (`change-user-stated`). The dream job cannot overrule the person.
6. Otherwise write it with trust `dream_inferred` and the cited turns as `sources`. The supersession rule then applies.

`bead queue` lists the review queue. `bead queue accept ID` writes the value as `user_stated`. `bead queue reject ID` writes a tombstone, so rule 2 stops the same proposal. A review item ID is a hash of the kind, key and value, so a repeated proposal is queued once.

Decay marks a fact `dormant` when it is not pinned, and nothing wrote, injected or reinforced it in `dream.decay_days` (default 60). `bead reinforce KEY` makes it current again. Dormant facts are not injected, but search still finds them.

The report in `store/reports/<date>.md` holds keys and version IDs, never values. Episodes in `store/episodes/` hold summaries, so `forget` deletes an episode file that contains a forgotten value. It also drops review items for the key or text.

For a hosted provider under launchd, set `dream.api_key_command`, for example `security find-generic-password -s bead-anthropic -w`. launchd does not pass shell variables.

## Curation session

`bead curate` starts a harness session, for example Claude Code, with the admin MCP server attached. The admin server has tools that the normal server does not have: `reinforce`, `pin`, `forget`, `seal`, `unseal`, `rekey`, `review_queue` and `history`. The session opens on the latest dream report and the review queue.

A plain `bead review` terminal mode gives the same actions without a model, for a person who does not want an agent in the loop.

### Curation implementation

`bead curate` writes `curate-mcp.json` in the bead home. It then runs `claude --mcp-config <file> --strict-mcp-config --append-system-prompt <prompt>`. `--print-config` prints the MCP configuration for another harness.

The launcher removes `ANTHROPIC_BASE_URL` from the child environment when it points at a loopback address. A curation session through the bead proxy would capture the memories it shows into the raw log. That capture would undo a forget.

The MCP server (`bead mcp`) is written by hand over stdio JSON-RPC, with no SDK. The normal server has `recall` and `remember`. The admin server adds `summary`, `search`, `history`, `pin`, `reinforce`, `forget`, `forget_matching`, `seal` and `list_sealed`. There is no `unseal` tool.

`forget`, `forget_matching` and `seal` work in two calls. The first call returns a preview and a confirm token. The second call with the token makes the change. A token works once, for the action it was issued for, and for 10 minutes. This puts the preview in front of the person before the change, even when the harness approves tool calls without asking.

`remember` in the normal server writes `agent_observed` facts. In the admin server it writes `user_stated` facts, because the person directs that session.

## Deletion

`bead forget <id-or-key>` does these steps in order:

1. Delete every version file of the fact.
2. Redact the source spans in the raw log that the fact cites.
3. Delete the matching rows from the index.
4. Write a tombstone to `tombstones.log`. The tombstone holds the key and a SHA-256 hash of the normalized value, not the value itself.

The store writes the tombstones before it deletes the files. A crash in between therefore cannot leave a fact without a tombstone.

The store refuses a write that matches a tombstone unless its trust is `user_stated`. Without this check, the next dream run extracts the deleted fact from raw history again. A person can still restore a fact by stating it again.

SQLite keeps deleted text in three places, so the index turns on three settings:

- `PRAGMA secure_delete=ON` overwrites freed pages with zeros.
- The FTS5 `secure-delete` option removes deleted rows from the full-text segments at once.
- After each forget, `PRAGMA wal_checkpoint(TRUNCATE)` empties the WAL file.

`TestForgetBlocksReextraction` reads the bytes of `index.db` after a forget. The test fails when the first two settings are removed.

A forget can also take match text: `bead forget --match TEXT`. It forgets every key with a version that contains the text. It also redacts every raw turn that contains the text. The match ignores case and whitespace, and the text must have 3 or more characters. The command shows all matches and asks for confirmation first.

The raw log search for a forget reads the files, not the index. The index holds only the first 4,000 characters of a turn. A redacted turn keeps its marker line, and its text becomes `[forgotten]`. The raw log takes a `flock` on `store/raw/.lock` for appends and redactions. A redaction therefore cannot lose a turn that the proxy appends at the same time.

`forget KEY` redacts a raw turn when the turn is in the `sources` of a version, or when the turn text contains the value of a version. A turn that states the same fact in other words is not found. `--match` covers that case.

The store must not be a git repository while forget is a promise. Git history keeps deleted content. If a person wants version control, the design adds an encrypted backup that `forget` can also rewrite.

## Security

- The proxy listens on `127.0.0.1` only.
- The proxy does not store API keys.
- Capture runs a secret scan before any write to disk.
- A `secret` fact is encrypted with age in `vault/sealed/`. The proxy never injects it, and no MCP tool returns it. Only the CLI can read it: `bead sealed show KEY` asks for the passphrase.
- Injected memory is wrapped and labelled as data, not instructions. A fact with `trust: dream_inferred` that holds instruction-like text goes to the review queue, not the store. This limits memory poisoning from tool output.
- `audit.log` records every write, supersede, injection and delete.

## Sealing

`bead vault init` creates a hybrid post-quantum age key pair (`age.GenerateHybridIdentity`). The public key goes to `vault/recipient.txt`. The private key goes to `vault/identity.age`, encrypted with an scrypt passphrase of 12 or more characters.

Sealing uses only the public key, so it needs no passphrase. Reading and unsealing need the passphrase. If the passphrase is lost, the sealed facts cannot be recovered.

Each version is one encrypted file, `vault/sealed/<key>/v<N>.md.age`. The next version number comes from the file names, so a secret write needs no decryption. The rule that the highest version is current also holds in the vault, so an old sealed version that still says `current` inside does no harm.

A key is either plaintext or sealed, never both:

- `bead seal KEY` encrypts every version, writes tombstones, and then deletes the plaintext.
- `bead write --sensitivity secret` first seals any plaintext versions of the key. It then encrypts the new version in memory. The secret value is never written to disk as plaintext.
- A plaintext write to a sealed key fails with `ErrSealed`.
- `bead unseal KEY` restores the versions as plaintext with sensitivity `private`, and sets their statuses again.

Sealing does not change the raw log. The conversation in which a person stated the secret stays in `store/raw/`, but the capture step redacts common credential formats first. To remove such a turn, run `bead forget --match TEXT` as well. `forget --match` does not search sealed values, because it does not decrypt them.

The vault file names show the keys and the version counts, for example `user/bank-pin`. The values stay encrypted. To hide the key names too, use a neutral key such as `user/secret-1`.

## Evaluation

Build the eval set before the proxy. The brief makes three claims that can be measured, so measure them on this system:

- Stale-value rate: the fraction of injections that contain a superseded value. The target is 0.
- Injection hit rate: the fraction of turns that need a memory where the proxy injected it.
- False-injection rate: the fraction of injected blocks that the turn did not need.

The set starts with about 50 scripted sessions, each with a known fact change and a later question that depends on it.

`bead eval FILE` runs a suite twice. The `supersession-rule` mode searches current versions only. The `similarity-only` mode searches every version, as a plain retriever does. The first suite, `evals/supersession.yaml`, has 10 scenarios and 11 queries:

| Mode | Hit@1 | Stale@1 |
| --- | --- | --- |
| supersession-rule | 100.0% | 0.0% |
| similarity-only | 45.5% | 54.5% |

The suite is small and hand-written, so the numbers show that the rule works. They do not measure retrieval quality.

Two suites measure cue-triggered injection:

- `evals/injection.yaml` has 18 facts and 39 turns. I wrote it and tuned the scorer against it.
- `evals/injection-heldout.yaml` has 28 facts and 60 turns for a different project. An agent wrote it without access to the scorer code. Half of its turns are tool calls with realistic output. The odd turns are used for development. The even turns are a test set, scored once per candidate.

The held-out test turns (30 turns) give these results:

| Gate | Recall | Precision | Turns with a false injection |
| --- | --- | --- | --- |
| Term coverage 0.25 (first version) | 0.53 | 0.21 | 40% |
| Evidence 1.0 (tuned on the first suite) | 0.88 | 0.25 | 63% |
| Embedding, `nomic-embed-text`, cos 0.60 | 0.59 | 0.43 | 43% |
| Embedding and evidence together | 0.71 | 0.41 | 40% |
| Evidence 1.2, source-weighted, peak (default) | 0.24 | 0.44 | 13% |

No gate reaches a usable balance on realistic turns. Tool output shares many project words with the facts, so similarity alone cannot tell whether a fact helps the turn. The evidence score on the first suite (recall 1.00, precision 0.87) came from overfitting.

The default is therefore precision-first. It injects at most 2 facts, and only on a strong match. Cue terms weigh 1 from the person's text, 0.6 from the assistant's text and tool input, and 0.3 from tool output. The score is the strongest shared term plus a quarter of the rest, and the project name does not count. A miss falls back to the pinned block and the `recall` tool. `TestInjectionSweep` guards the default against regression. The embedding experiment is `TestEmbeddingGate`, and it runs only with `BEAD_EMBED_EXPERIMENT=1`.

### Rerank

With `rerank.enabled: true`, every candidate with an evidence score of 0.5 or more, up to 5, goes to a chat model. The model returns the candidates that help the next step. The prompt says that most turns need no fact. Tool output is cut to 600 characters per block, and the turn to 4,000. If the call fails or passes `rerank.timeout_ms` (default 4000), the strict default gate decides. The rerank uses the dream model unless the `rerank` section names its own.

Gate 0.5 was chosen on the dev turns. On the held-out test turns, with `deepseek/deepseek-v4.1-flash-1017` through OrcaRouter, it gave these results:

| Gate | Recall | Precision | Turns with a false injection | Latency per call |
| --- | --- | --- | --- | --- |
| Strict default, no rerank | 0.24 | 0.44 | 13% | 0 |
| Evidence 0.5, then rerank | 0.88 | 0.88 | 7% | p50 2.5 s, p90 3.4 s |

The rerank blocks the request, so it adds its latency to each turn that has a candidate: 28 of 30 test turns. The proxy locks per conversation, so parallel subagents do not wait for each other. `TestRerank` runs the measurement with `BEAD_RERANK_EXPERIMENT=1`, and the trace records `rerank_ms` for each request.

The next step for injection is labels from real traces.

## Build order

1. Store, supersession rule, BM25 index, CLI and eval harness. Done.
2. Proxy for the Anthropic Messages API, with capture, injection and streaming. Done. Raw turns are indexed and searched as well.
3. MCP server with `recall` and `remember`. Done as part of step 5.
4. Dream job and the report. Done, tested with a fake model only.
5. Curation session, forget and sealing. Done.
6. OpenAI-compatible proxy route.
7. Multi-user: authentication on the proxy, and a store root for each owner.

## Implementation

The code is Go with `CGO_ENABLED=0`. It has two direct dependencies:

- `gopkg.in/yaml.v3` v3.0.1 for frontmatter and configuration.
- `modernc.org/sqlite` v1.61.1, a pure-Go SQLite with FTS5.

File locking uses `flock` and is implemented for unix only.

## Open questions

- The OKF field mapping for a later export.
- The default dream model for each provider.

## Known gaps

- No real model has run the dream prompt yet. The quality of extraction and key reuse is not measured. An extraction eval with recorded sessions is needed before the nightly job runs without review.
- Episodes are written but not yet indexed or injected.
- `forget KEY` finds raw turns only by citation or by exact value text. A paraphrase stays until `forget --match` removes it.
- Deleted files are unlinked, not overwritten. On APFS and on SSDs, overwriting does not erase the old blocks either. Full-disk encryption is the control for data at rest.
- The curation session sends fact values and the matching turn text to the model provider. Sealed values are not sent.
- Without the rerank, cue-triggered injection has low recall. With it, a turn with candidates waits about 2.5 s. See "Evaluation".
- IDF is computed over the stored facts only. With few facts it is noisy. Raw history as a background corpus would make it steadier.
- The proxy stores state files for every conversation and never deletes them.
- The proxy does not read the `cache_control` breakpoints. It relies on two facts: it appends to the end of the system prompt, and it changes only the newest user message.
