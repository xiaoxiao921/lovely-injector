# Lovely-lib is a runtime lua patching system

## Patches

*Note that the patch format is unstable and prone to change until Lovely is out of early development.*

*Patch files* define where and how code injection occurs within the game process. A good (complex) example of this can be found in the Steamodded repo [here](https://github.com/Steamopollys/Steamodded/tree/main/lovely).
```toml
[manifest]
version = "1.0.0"
priority = 0

# Define a var substitution rule. This searches for lines that contain {{lovely:var_name}}
# (var_name from this example, it can really be anything) and replaces each match with the
# provided value.
# This example would transform print('{{lovely:var_name}}') to print('Hello world!').
#
# USEFUL: For when you want to reduce the complexity of repetitive injections, eg. embedding
# release version numbers in multiple locations.
[vars]
var_name = "Hello world!"

# Inject one or more lines of code before, after, or at (replacing) a line which matches
# the provided pattern.
#
# USEFUL: For when you need to add / modify a small amount of code to setup initialization
# routines, etc.
[[patches]]
[patches.pattern]
target = "game.lua"
pattern = "self.SPEEDFACTOR = 1"
position = "after"
payload = '''
initSteamodded()
print('{{lovely:var_name}}')
'''
match_indent = true
times = 1

# Inject one or more lines of code before, after, at, or interwoven into one or more
# Regex capture groups.
# - I recommend you to use a Regex playground like https://regexr.com to build
#   your patterns.
# - Regex is NOT EFFICIENT. Please use the pattern patch unless absolutely necessary.
# - This patch has capture group support.
# - This patch does NOT trim whitespace from each line. Take that into account when
#   designing your pattern.
#
# USEFUL: For when the pattern patch is not expressive enough to describe how the
# payload should be injected.
[patches.regex]
target = "tag.lua"
pattern = "(?<indent>[\t ]*)if (?<cond>_context.type == 'eval' then)"
position = 'at'
line_prepend = '$indent'
payload = '''
local obj = SMODS.Tags[self.key]
local res
if obj and obj.apply and type(obj.apply) == 'function' then
    res = obj.apply(self, _context)
end
if res then
    return res
elseif $cond
'''
times = 1

# Append or prepend the contents of one or more files onto the target.
#
# USEFUL: For when you *only* care about getting your code into the game, nothing else.
# This does NOT inject it as a new module.
[[patches]]
[patches.copy]
target = "main.lua"
position = "append"
sources = [
    "core/core.lua",
    "core/deck.lua",
    "core/joker.lua",
    "core/sprite.lua",
    "debug/debug.lua",
    "loader/loader.lua",
]
```

### TL;DR - Patch variants

- Use `pattern` patches to surgically embed code at specific locations within the target. Supports `*` (matches 0 or more occurrences of any character) and `?` (matches exactly one occurrence of any character) wildcards.
- Use `regex` patches *only* when the pattern patch does not fulfill your needs. This is basically the pattern patch but with a backing regex query engine, capture groups and all.
- Use `copy` patches when you need to copy a large amount of position-independent code into the target.

### Patch files

Patch files are loaded from plugins directory. Lovely will load any patch files present within `plugins/ModName/lovely/` or load a single patch from `plugins/ModName/lovely.toml`. If multiple patches are loaded they will be injected into the game in the order in which they are found.

Paths defined within the patch are rooted by the folder of the toml patch file. For example, `core/deck.lua` resolves to `plugins/ModName/core/deck.lua`.

### Patch targets

Each patch definition has a single patch target. These targets are the relative paths of source files when dumped from the game with a tool like 7zip. For example, one can target a top-level file like `main.lua`, or one in a subdirectory like `engine/event.lua`.

### Patch debugging

Lovely dumps patched lua source files to `lovely_dump`. Logs are written to `lovely.log`.