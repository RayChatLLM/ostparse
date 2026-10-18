# ostparse — RayChat plugin for searching Outlook OST/PST files

Search and analyze email inside Outlook OST/PST data files directly on disk:
no Outlook, no native dependencies, any OS. The plugin vendors
[ostparse](https://github.com/), a pure-stdlib streaming [MS-PST] reader with
a full-text sidecar index, so a query against a 10 GB store answers in
milliseconds once the index exists. The OST/PST file is only ever read.

Supported host: RayChat SDK 4. Python 3.10+. Pure standard library — no pip
install, no native code.

## Install

In a RayChat chat, install the release ZIP (downloads from GitHub, verifies its
hash, then imports):

```text
/plugins install github:RayChatLLM/ostparse@v1.0.0
```

or from a downloaded archive:

```text
/plugins install /path/to/ostparse-1.0.0.zip
```

Then `/ostparse open /path/to/mailbox.ost` and `/ostparse search ...`. Manage it
with `/plugins disable|enable|uninstall ostparse`.

## Model action and operator command

```json
{"action": "ostparse", "command": "search from:alice \"budget review\" received:last month"}
```

```text
/ostparse open /data/mailbox.ost
/ostparse search hasattachment:yes /inv-\d{4}/ --facet folder
/ostparse show 0x200024 --full
/ostparse export ./out from:alice ext:pdf --limit 50
```

## Subcommands

| Command | Does |
| --- | --- |
| `open FILE` | Select the store for this session (path is remembered in session state); reads any OST/PST whether or not it carries an open-password |
| `close` | Forget the open store |
| `info` | Header/format details as JSON |
| `tree` | Folder hierarchy with message counts and `nid`s |
| `index [rebuild]` | Build or incrementally update the sidecar index `FILE.ostidx` |
| `search QUERY [--limit N --offset N --sort KEY --facet KIND --exact --json --no-snippets]` | Full-text search; one numbered line per hit ending in `nid=0x...` |
| `count QUERY` | Exact number of matches |
| `show NID [--full] [--headers]` | One message: addresses, attachments, body (clipped unless `--full`) |
| `export DIR QUERY [--limit N]` | Write matching messages as RFC 5322 `.eml` files |
| `stats` | Walk the whole store: folder/message/attachment totals |
| `help` / `help query` | Usage / full query-language reference |

`QUERY` is Outlook Instant Search (AQS) syntax plus `/regex/`: fields
(`from:` `to:` `subject:` `body:` `attachment:` `ext:` `in:` `folder:`),
phrases, wildcards, boolean `OR NOT -term ()`, dates
(`received:last week`, `date:2024-01-01..2024-03-31`), sizes
(`messagesize:>5MB`), flags (`hasattachment:yes`, `is:unread`), `kind:`,
`messageclass:` and `nid:0x...`.

Settings (manifest defaults, override with `plugins.settings.ostparse`):
`limit` (hits per page, 20), `body_chars` (show clip, 2000), `workers`
(index-build processes, 1), `export_cap` (200), `max_chars` (output clip,
16000), `tree_lines` (400).

Notes for operators: no password is ever needed. An OST/PST "open password"
(`PidTagPstPassword`) is only a weak CRC-32 that gates Outlook's own UI — it
does not encrypt the store — so `open FILE` reads the content either way and
simply reports `password_protected` in `open`/`info`. (A genuinely encrypted
store — Windows Information Protection, `bCryptMethod` 0x10 — is different and
is reported with guidance to decrypt it on its Windows host.) Outlook holds its
live OST open exclusively — work on a copy or close Outlook. Searching reads
only the index; `show`/`export` open the store file.

## Verification walkthrough (isolated workspace)

Point the plugin at any `.ost`/`.pst` file (a real Outlook OST, or a public
sample such as java-libpst's `example-2013.ost`). The same `commands.run` code
the plugin registers can be driven standalone, each argument one subcommand
sharing session state:

```sh
python3 -m ostparse_raychat \
  "open /path/to/mailbox.ost" \
  "index" \
  "search hasattachment:yes --limit 5 --facet folder" \
  "count kind:email" \
  "show 0x200024 --full" \
  "export /tmp/out ext:pdf --limit 10" \
  "close"
```

Inside RayChat:

```text
/plugins check /path/to/ostparse
/plugins link  /path/to/ostparse
/ostparse open /path/to/mailbox.ost
/ostparse search budget --limit 5
```

Ask the model “find messages with PDF attachments from last month in
/path/to/mailbox.ost and show the newest one” to exercise the tool path, then
`/plugins pack /path/to/ostparse /tmp/ostparse-1.0.0.zip`,
`/plugins uninstall ostparse`, `/plugins install /tmp/ostparse-1.0.0.zip`,
re-run a search (the session state survives), `/plugins disable ostparse`,
`/plugins enable ostparse`, `/plugins uninstall ostparse`.

Edit-and-reload: change `defaults.limit` in `plugin.json` while linked; the
next `/ostparse search` uses the new page size. Long index builds poll the
host cancellation callback, so double-Escape stops them.
