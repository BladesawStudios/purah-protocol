# purah-protocol wire protocol, version 1

The conversation between Prism (the client) and the purah-protocol module (the server, inside the game). The hooks it controls are
listed in [the symbol book](../data/totk/121/book.tsv). The module's side is `probe/src/protocol.hpp` and Prism's is its `Prism.Debug`
project. **The two are written by hand and must match this document; the golden vectors at the end are checked against both.**

## Transport

* TCP, port **54312**. Prism connects; the module listens (on Ryujinx, `127.0.0.1:54312`).
* One client at a time. A second connection is refused until the first sends `Goodbye` or drops.
* Everything is little-endian. There is no padding and no alignment.
* The module never blocks the game on the socket (design doc, "Wire protocol"): it reads and writes a bounded
  number of bytes per frame. A client that stops reading loses events, not the game's frame rate; see `Overflow`.

## Frame

```
offset  size  field
0       4     length   payload bytes that follow the header (0 .. 65536)
4       2     type     MessageType
6       2     flags    bit0 Response, bit1 Event; all other bits 0
8       4     seq      requester's number; a Response echoes it; an Event carries the module's own counter
12      n     payload
```

A frame whose `length` exceeds 65536, or whose payload does not decode exactly (a field short, or bytes left
over), is a protocol error: the receiver sends `Error` and `Goodbye` and closes. Unknown `type` values are
skipped using `length` (so a newer peer can add messages), except that a request with an unknown type is
answered with `Error` (`UnknownMessage`).

**Strings** are a `u16` byte count then that many UTF-8 bytes, no terminator, at most **1024** bytes.
**Bool** is one byte, `0` or `1`.

## Session

| Type | Name | Direction | Payload |
| --- | --- | --- | --- |
| `0x0001` | Hello | both | `u16 protocol` (1), `u16 flags` (0), `u32 buildFingerprint`, `u32 moduleVersion`, `u32 bookHash`, `u32 capabilities`, `str token`, `u64 imageBase` |
| `0x0002` | Goodbye | both | `u16 reason` |
| `0x0003` | Ping | both | `u64 token` |
| `0x0004` | Pong | both | `u64 token` (echo) |
| `0x00FF` | Error | both | `u16 code`, `str text` |

The client sends `Hello` first, with the pairing `token` from the module's `config.ini` (empty if none is
set). The module answers `Hello` (`flags` Response, `token` empty) or `Error` (`BadToken`,
`BadVersion`, `Busy`) and closes. `buildFingerprint` is the host's fingerprint of the running game
(`0x181D91D8` for TotK 1.2.1); the client refuses to arm probes if it does not match its book. `bookHash` is
the module's hash of the address table it was built with; a mismatch is reported to the user, not refused.
`imageBase` is where the game's main module is loaded in the process (a book offset plus this is a runtime address; Prism subtracts it from callers and pointers). `capabilities`: bit0 **write** (Poke and ForceReturn allowed), bit1 **break** (Break mode allowed).

`reason` for Goodbye: `0` normal, `1` protocol error, `2` superseded by another client, `3` module shutting down.
`Error.code`: `1` UnknownMessage, `2` BadToken, `3` BadVersion, `4` Busy, `5` Malformed, `6` WriteDisabled,
`7` BreakDisabled, `8` NotInBuild, `9` Internal.

## Configuration (the live control plane)

The client sends the **whole desired configuration** with a revision number; the module makes it true at the
next tick boundary on the game thread and reports what it managed. The module's current truth is available at
any time with `GetConfig`.

| Type | Name | Direction | Payload |
| --- | --- | --- | --- |
| `0x0010` | GetConfig | client | none |
| `0x0011` | Config | module | `u32 revision`, `u16 count`, `count` x **ProbeEntry** |
| `0x0012` | SetConfig | client | `u32 revision`, `u16 count`, `count` x **ProbeEntry** |
| `0x0013` | ConfigApplied | module | `u32 revision`, `u16 count`, `count` x (`u32 probeId`, `u8 result`) |
| `0x0040` | ListProbes | client | none |
| `0x0041` | Probes | module | `u16 count`, `count` x (`u32 probeId`, `u8 state`, `u8 reason`) |

**ProbeEntry**: `u32 probeId`, `u8 mode`, `u8 flags`, `u16 rateLimitPerSecond` (0 = unlimited),
`u8 depth`, `u8 reserved` (0), `u64 forceValue`, `str subject`.

* `probeId` is the row number of the hook in the symbol book (`book-1.2.1.tsv`, counting data rows from 0).
* `mode`: `0` Off, `1` Trace, `2` Break, `3` ForceReturn. A probe not listed in a `SetConfig` is Off.
* `flags`: bit0 capture arguments, bit1 capture the return value, bit2 capture the caller (`LR`), bit3 capture the subject (the actor name, in `ProbeHit.subject`).
* `depth` is the call-tree depth for a call-site probe (0 = this probe only).
* `forceValue` is the value a ForceReturn probe returns; ignored otherwise.
* `subject` is an actor name filter (at most 48 bytes); empty means every actor. Otherwise a call is recorded only if its actor's name contains the
  filter. The module finds the actor three ways, in order: from the call itself (`this` is an actor or a component, or the call is given a name),
  from the actor the calling thread is initialising (BaseProc::initialize, ActorBase::initializeActor_ and initializeComponent open a scope that
  covers every other probed call on that thread), or not at all, in which case a filter rejects the call. A configuration with any filter makes the
  module hook those scope functions too. Call sites have no `this` and use the thread's scope.

`result` / `reason`: `0` Applied, `1` RefusedPattern (the bytes at the address are not the vanilla ones),
`2` RefusedPoolFull, `3` RefusedNotInBuild, `4` RefusedUnknownProbe, `5` RefusedWriteDisabled,
`6` RefusedBreakDisabled, `7` RefusedUnsupported (the probe exists but not in that mode, e.g. ForceReturn on a call site). `Probes.state`: `0` Absent (not in this build), `1` Live (installed, enabled or
not), `2` Refused.

Rules the module follows, not options: a global rate limiter disarms any probe that exceeds its
`rateLimitPerSecond` and says so with a `Log` event; **on disconnect every Break and ForceReturn probe drops
to Trace**; revisions only grow (a `SetConfig` with a revision not greater than the current one is answered with
`ConfigApplied` of the current revision and no changes).

## Watching one actor

The client names an actor; the module follows it through every step of its initialisation and says why it failed. The steps are the rows of
[steps.psv](steps.psv), shared by both sides: a `stepId` is the row's position in that file, and the `bookHash` in Hello covers the book's
offsets followed by the steps' offsets, so a module and a Prism built from different catalogs disagree visibly.

| Type | Name | Direction | Payload |
| --- | --- | --- | --- |
| `0x0050` | WatchActor | client | `u8 action` (1 watch, 0 stop), `str name` |
| `0x0051` | WatchAck | module | `u8 status`, `u16 armed`, `u16 refused`, `str name`, `str note` |
| `0x0105` | ActorStep (event) | module | `u32 stepId`, `u8 phase` (0 enter, 1 leave), `u8 outcome`, `u32 threadId`, `u64 tick`, `u64 value`, `str detail` |
| `0x0106` | ActorVerdict (event) | module | `u8 outcome`, `u32 failedStep` (`0xFFFFFFFF` none), `u64 code`, `str summary`, `u16 count`, `count` x `str line` |

* `WatchActor` hooks every step of the catalog (and the functions that open an actor's scope, and the game's two diagnostic channels) on the
  module's tick thread, then answers `WatchAck`: `status` 0 Watching, 1 Stopped, 2 RefusedName (empty or over 47 bytes), 3 Partial (some step hooks
  were refused in this game build; `refused` counts them, `note` says so). `armed` counts the hooks placed. The watch is live as soon as the ack is sent,
  and ends on `WatchActor` stop or when the client disconnects. `name` is matched as a substring of the actor's name.
* A step belongs to the watched actor if its own `this` is the actor or one of its components, or if the calling thread is inside the actor's
  initialisation (the same scope the actor filter uses). `ActorStep` reports each step on entering (`outcome` 0) and leaving (`outcome` 1 ok, 2
  failed, 3 warning), with the raw return in `value` and the component a step was about in `detail`. A step whose result the game tests in the next
  instruction (a `tbz`) is entered but has no leave event.
* Each step's catalog rule judges its result: `zero` fails on a zero (false or null) return, `code` on any return but 1, `warn` reports a zero but the
  game carries on, `none` only records.
* When `BaseProc::initialize` returns for the watched actor, `ActorVerdict` follows. `outcome` 0 Initialised, 1 Failed, 2 NeverStarted. For a failure,
  `failedStep` is the first step to fail that is not a container (nested steps leave before the step that contains them, so the first failure to leave is the deepest cause; a container such as `initializeActor_` fails because something inside it did, and is named only when nothing inside it reported a failure, in which case the lines add a checklist of the stages the game does not report),
  `code` the initialisation code, `summary` one sentence, and the lines in order: the cause (the step's meaning from the catalog), where it happened,
  what the code means, what the decompiles say about the failing component (every one of the 206 component classes has an entry, generated into `components.psv` by `tools/docgen/build_component_reasons.py`), what else failed after it, and the game's own diagnostics raised on the actor's thread during that initialisation. A request
  that is refused outright, or is not followed by an initialisation within 20 s, is a verdict of its own (`NeverStarted`).

## Control while stopped, memory

| Type | Name | Direction | Payload |
| --- | --- | --- | --- |
| `0x0020` | Resume | client | `u64 hitId` |
| `0x0021` | StepOut | client | `u64 hitId` |
| `0x0022` | ForceReturn | client | `u64 hitId`, `u64 value` |
| `0x0030` | ReadMem | client | `u64 address`, `u32 length` (at most 4096) |
| `0x0031` | MemData | module | `u64 address`, `u8 status`, `u32 length`, `length` bytes |
| `0x0032` | Poke | client | `u64 address`, `u16 count` (at most 16), `count` expected bytes, `count` new bytes |
| `0x0033` | PokeResult | module | `u64 address`, `u8 status` |

`hitId` is the id of a `ProbeHit` or `ProbeReturn` event whose `hitId` is non-zero: the thread that produced it is stopped (Break mode)
and waits. `Resume` runs the call; `StepOut` runs it and stops again at its return (a `ProbeReturn` with a new `hitId`); `ForceReturn` skips
the call and returns `value` (at a return stop it replaces the value the call returned; at a call-site probe ForceReturn is refused when
arming, because a call site cannot skip its call). A stopped thread resumes by itself after 30 s with a `Log` event, or at once when the client disconnects. An answer for a
hit that is not stopped gets `Error` (`Internal`). If the stopped thread is the one that runs the module's tick, the module serves the connection from inside the wait.
`MemData.status`: `0` ok (the bytes returned may be fewer than asked if the readable region ends), `1` unmapped (length 0), `2` too long. The module asks the host which pages are mapped and readable before touching them, so a bad address is a status, never a fault. `PokeResult.status`: `0` written, `1` the
current bytes differ from `expected` (nothing written), `2` refused (not mapped, not writable, or the host refused the patch), `3` write disabled.
Addresses inside the game image are written through the host's checked patch (which records who changed what); other memory is compared and
written directly. Every successful write also produces a `Log` event.
Addresses are absolute; Prism adds the image base the host reports.

## Events (module to client, flags Event)

| Type | Name | Payload |
| --- | --- | --- |
| `0x0100` | ProbeHit | `u32 probeId`, `u32 threadId`, `u64 tick`, `u64 caller`, `u64 hitId` (0 unless the thread is stopped), `u8 argc` (at most 8), `argc` x `u64`, `str subject` |
| `0x0101` | ProbeReturn | `u32 probeId`, `u32 threadId`, `u64 tick`, `u64 value`, `u8 failure`, `u64 hitId` (0 unless the thread stopped at this return) |
| `0x0102` | Overflow | `u32 dropped` (events dropped since the last Overflow) |
| `0x0103` | Log | `u8 level` (0 info, 1 warning, 2 error), `str text` |
| `0x0104` | Notice | `u8 level`, `u32 category`, `u32 line`, `str file`, `str message`, `str path` |

`tick` is the game's system tick. `caller` is the caller's return address (an absolute address). `failure` is
1 when the module's rule for the probe says a return of this value is a failure (a `bool` false or a null pointer from a function whose book note says so). The module decides; Prism does not guess.
`Notice` also carries the effects system's errors, captured at `xlink2::System::addError` (lifecycle doc part 4,
section P): `file` is `xlink2::System::addError`, `category` the error category, `line` 0, `message` the formatted
text and `path` the link user (the actor). Otherwise `Notice` is the game's own parameter-system diagnostic, captured at `sead::NoticeContext::NoticeContext`
(part 1 of the lifecycle doc, section 13): `level` and `category` as the game gives them, `file` and `line`
the source position in the game, `message` its text, `path` the document being parsed.

## Golden vectors

Both implementations must produce exactly these bytes (frames as hex, header first).

**Ping** (`seq` 7, flags 0, token `0x0102030405060708`):

```
08000000 0300 0000 07000000 0807060504030201
```

**Hello** (`seq` 1, flags 0; protocol 1, flags 0, fingerprint `0x181D91D8`, moduleVersion 1, bookHash
`0xAABBCCDD`, capabilities 3, token `"x"`, imageBase `0x7100000000`):

```
1F000000 0100 0000 01000000 0100 0000 D8911D18 01000000 DDCCBBAA 03000000 0100 78 0000000071000000
```

**ProbeHit** (`seq` 9, flags Event; probeId 5, threadId 2, tick `0x1122334455667788`, caller `0x71007FD97C`,
hitId 0, argc 2, args `0x10` and `0x20`, subject `"ab"`):

```
35000000 0001 0200 09000000 05000000 02000000 8877665544332211 7CD97F0071000000 0000000000000000 02
1000000000000000 2000000000000000 0200 6162
```

The payload is 4+4+8+8+8+1+16+2+2 = 53 = `0x35` bytes. Spaces are for reading only.
