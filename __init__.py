"""RayChat SDK v4 plugin: search and analyze Outlook OST/PST files on disk.

Pure standard library: a vendored copy of ostparse (a streaming [MS-PST]
reader with a full-text sidecar index) does the file work. ``register``
binds the RayChat command and tool; everything below ``commands.run`` also
works without RayChat via ``python -m ostparse_raychat``.
"""


def register(api: object) -> None:
    """Register the plugin with RayChat (imported lazily so the package
    stays importable without the RayChat SDK, e.g. for the CLI).
    """
    from .registration import register as _register

    _register(api)
