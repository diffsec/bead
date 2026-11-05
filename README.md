# bead

bead is a memory service for coding agents. It keeps memory as Markdown files on disk. A local proxy delivers the memory to the model on every turn, so the agent does not have to ask for it.

- Facts have typed keys and versions. The current value is always the highest version, so search never returns a superseded value.
- BM25 search (SQLite FTS5) covers the facts and the raw history of earlier sessions.
- The proxy works with any harness that lets you set the Anthropic base URL, including Claude Code with a Team or Enterprise subscription.
- A nightly dream job extracts facts from new sessions with Ollama, Anthropic or an OpenAI-compatible model. A change to a value that you stated goes to a review queue.
- `forget` removes a value from facts, raw history, the index, episodes and the review queue. `seal` encrypts a fact with age.

[DESIGN.md](DESIGN.md) explains the design, the rules and the known gaps.

## Install

bead needs Go 1.27 or later and builds without cgo.

```sh
go install github.com/diffsec/bead/cmd/bead@latest
bead setup
```

`bead setup` sets up the machine in one step:

- It writes a default `~/.bead/config.yaml` if none exists.
- It offers to create the vault for sealed facts.
- It installs and loads the proxy and the nightly job as launchd agents.
- It adds a `claude` shell function that routes Claude Code through the proxy.

Run it again at any time. It keeps an existing configuration and vault. Open a new terminal after the setup.

## Configure the dream model

Put the model configuration in `~/.bead/config.yaml`:

```yaml
dream:
  provider: openai          # ollama | anthropic | openai
  model: your-model
  base_url: https://example.com/v1
  api_key_command: security find-generic-password -s bead-openai -w
```

The nightly job runs under launchd, which does not pass shell variables. Use `api_key_command` for a hosted provider.

## Use

```sh
bead write --key project/demo/db-port "The dev database listens on port 5434."
bead search "database port"
bead history project/demo/db-port
bead curate                 # review, pin, seal and forget with Claude Code
bead queue                  # proposals from the dream job that wait for you
bead forget --match "text"  # remove text from every place bead stores it
```

Run `bead help` for every command.

## Test

```sh
CGO_ENABLED=0 go test ./...
bead eval evals/supersession.yaml
```
